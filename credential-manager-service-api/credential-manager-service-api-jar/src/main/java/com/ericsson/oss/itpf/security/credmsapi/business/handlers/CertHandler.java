/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.business.handlers;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.*;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.CertHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialWriterFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

public class CertHandler {

    private static final Logger LOG = LogManager.getLogger(CertHandler.class);

    public Certificate[] getSignedCertificate(final CredMServiceWrapper service, final PKCS10CertificationRequest csr, final String entityName, final boolean certificateChain, String otp)
            throws CertificateEncodingException, IssueCertificateException, OtpExpiredException, OtpNotValidException {

        if (service == null) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_WRAPPERNOTNULL, entityName);
            throw (new IssueCertificateException("getSignedCertificate: service is NULL"));
        }

        /**
         * Convert PKCS10Certificate to String
         */
        CredentialManagerPKCS10CertRequest csrString = null;
        try {
            csrString = new CredentialManagerPKCS10CertRequest(csr);
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CONVERT_CSR);
            throw (new IssueCertificateException("getSignedCertificate: PKCS10 build exception ", e));
        }

        // TODO substitute the method with the one with chain
        // it will return not just a certificate but a list
        final CredentialManagerX509Certificate[] certArray = service.getCertificate(csrString, entityName, certificateChain, otp);

        /*
         * CredentialManagerX509Certificate getCertificate
         * (CredentialManagerPKCS10CertRequest csr, String entityName, String
         * issuer, int validity);
         */

        if (certArray == null || certArray.length == 0) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_SIGNEDCERT, entityName);
            throw (new CertificateEncodingException("getSignedCertificate: certificate from Service is NULL or EMPTY"));
        }

        Certificate convertedCertArray[] = new Certificate[certArray.length];

        for (int i = 0; i <= certArray.length - 1; i++) {
            /**
             * Convert String to Certificate
             */
            convertedCertArray[i] = certArray[i].retrieveCertificate();

            // writeKeyAndCertificate(cert, ksInfoList);
        }

        return convertedCertArray;
    }

    /**
     * @param cert
     * @param ksInfoList
     * @param alias
     */
    public void writeKeyAndCertificate(final Certificate[] certChain, final KeyPair keyPair, final KeystoreInfo ksInfo) throws CertHandlerException {

        final String ksLocation = ksInfo.getKeyAndCertLocation();
        final String keyLocation = ksInfo.getPrivateKeyLocation();
        final String certLocation = ksInfo.getCertificateLocation();
        final String ksPassword = ksInfo.getKeyStorePwd();
        final CertificateFormat ksType = ksInfo.getCertFormat();

        try {
            final CredentialWriterFactory credWF = new CredentialWriterFactory();
            final CredentialWriter credWKS = credWF.getCredentialwriterInstanceForCert(StorageFormatUtils.getCertFormatString(ksType), ksLocation, certLocation, keyLocation, ksPassword);

            credWKS.storeKeyPair(keyPair.getPrivate(), certChain, ksInfo.getAlias());

        } catch (final StorageException e) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_WRITE_CERTIFICATE);
            throw (new CertHandlerException("certificate writing failed"));
        }
    }

    /**
     * clearKeystores
     * 
     * @param trustStoreInfo
     * @param keystoreInfo
     * @throws TrustHandlerException
     */
    public void clearKeystore(final KeystoreInfo keystoreInfo) throws CertHandlerException {

        final String ksAlias = keystoreInfo.getAlias();
        final String ksPassword = keystoreInfo.getKeyStorePwd();
        final CertificateFormat ksType = keystoreInfo.getCertFormat();

        // the single file is used
        if (keystoreInfo.isKeyAndCertLocationValid()) {
            final String ksLocation = keystoreInfo.getKeyAndCertLocation();
            this.deleteEntry(ksLocation, ksAlias, ksPassword, ksType);
        }

        // two files are used: delete entry called two times
        if (keystoreInfo.isFileCoupleValid()) {
            String ksLocation = keystoreInfo.getPrivateKeyLocation();
            this.deleteEntry(ksLocation, ksAlias, ksPassword, ksType);
            ksLocation = keystoreInfo.getCertificateLocation();
            this.deleteEntry(ksLocation, ksAlias, ksPassword, ksType);
        }

        // folder management
        //if (keystoreInfo.isKeyStoreFolderValid())  {
        //    // use keystore delete method
        //    keystoreInfo.removeFolderEntries();
        //}

    } // end of deleteKeystoreEntry

    private void deleteEntry(final String ksLocation, final String ksAlias, final String ksPassword, final CertificateFormat ksType) throws CertHandlerException {

        final CredentialWriterFactory credWF = new CredentialWriterFactory();

        try {
            // keyStore writer
            final CredentialWriter credWKS = credWF.getCredentialwriterInstanceForCert(StorageFormatUtils.getCertFormatString(ksType), ksLocation, ksPassword);
            // delete only the entry with the given alias (or aliases that contain this alias)
            credWKS.deleteEntry(ksAlias);

        } catch (final StorageException e) {
            // the keystore 
            throw (new CertHandlerException("deleteKeystoreEntry: " + e.getMessage()));
        }

        // check for empty file after deleting the entries 
        // (becuase if the file exists but its empty it can not be used by keytool)
        final File file = new File(ksLocation);
        if (file.length() == 0) {
            file.delete();
        }

    }

} // end of CertHandler

