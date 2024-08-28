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
import java.util.*;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialWriterFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.*;

public class TrustHandler {

    private static final Logger LOG = LogManager.getLogger(TrustHandler.class);

    /**
     * getTrustCertificates
     * 
     * @param service
     * @param entityProfileName
     * @return
     * @throws TrustHandlerException
     */
    public CredentialManagerTrustMaps getTrustCertificates(final String entityProfileName, final CredMServiceWrapper service) throws TrustHandlerException {

        /**
         * Call getTrustCertificates
         */
        if (service == null) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_WRAPPERNOTNULL, entityProfileName);
            throw (new TrustHandlerException("getTrustCertificates: service is NULL"));
        }
        System.out.println("getTrust for entity profile name: " + entityProfileName);
        LOG.info("getTrust for entity profile name: " + entityProfileName);
        final CredentialManagerTrustMaps caMaps = service.getTrustCertificates(entityProfileName, CredentialManagerProfileType.ENTITY_PROFILE);

        if (caMaps == null) {
            throw (new TrustHandlerException("getTrustCertificates: caMaps is NULL"));
        }
        return caMaps;
    }

    /**
     * 
     * @param tsInfoList
     * @param caMapChain
     * @throws TrustHandlerException
     */
    public void writeTrustCertificates(final TrustStoreInfo tsInfo, final CredentialManagerTrustMaps caMaps) throws TrustHandlerException {
        try {
            final CredentialWriterFactory credWF = new CredentialWriterFactory();

            final String tsLocation = tsInfo.getTrustFileLocation();
            final String tsFolder = tsInfo.getTrustFolder();
            final String tsPassword = tsInfo.getTrustStorePwd();
            final TrustFormat tsType = tsInfo.getCertFormat();

            // TS writer
            final CredentialWriter credWTS = credWF.getCredentialwriterInstanceForTrust(StorageFormatUtils.getTrustFormatString(tsType), tsFolder, tsLocation, tsPassword);

            if (tsInfo.isTrustSourceInternalAndExternal()) {

                this.trustChainWrite(tsInfo, credWTS, caMaps.getInternalCATrustMap());
                this.trustChainWrite(tsInfo, credWTS, caMaps.getExternalCATrustMap());
            } else if (tsInfo.isTrustSourceInternal()) {
                this.trustChainWrite(tsInfo, credWTS, caMaps.getInternalCATrustMap());
            } else if (tsInfo.isTrustSourceExternal()) {
                this.trustChainWrite(tsInfo, credWTS, caMaps.getExternalCATrustMap());
            } else {
                throw (new TrustHandlerException("writeTrustCertificates: invalid source"));
            }

        } catch (final StorageException e) {
            throw (new TrustHandlerException("writeTrustCertificates: " + e.getMessage()));
        }
    }

    /**
     * @param tsInfo
     * @param credWTS
     * @param caMapChain
     * @throws StorageException
     */
    private void trustChainWrite(final TrustStoreInfo tsInfo, final CredentialWriter credWTS, final Map<String, CredentialManagerCertificateAuthority> caMapChain) throws StorageException {
        if (!caMapChain.isEmpty()) {
            final Iterator<Entry<String, CredentialManagerCertificateAuthority>> iterator = caMapChain.entrySet().iterator();
            while (iterator.hasNext()) {
                final Entry<String, CredentialManagerCertificateAuthority> mapEntry = iterator.next();
                final String subject = mapEntry.getKey();

                if (caMapChain.get(subject).getCACertificateChain().size() == 1) {
                    // use the subject as name of alias or file
                    final CredentialManagerX509Certificate cacert = caMapChain.get(subject).getCACertificateChain().get(0);
                    credWTS.addTrustedEntry(cacert.retrieveCertificate(), this.composeTrustAlias(tsInfo.getAlias(), subject));
                } else {
                    for (final CredentialManagerX509Certificate cacert : caMapChain.get(subject).getCACertificateChain()) {

                        /*
                         * LOG.debug("Entry from the chain: " +
                         * cacert.getCertificate().getSubjectDN());
                         */
                        // use the whole distinguishname + serialnumber
                        final String certificateSubject = cacert.retrieveCertificate().getSubjectDN().getName() + "_" + cacert.retrieveCertificate().getSerialNumber();
                        credWTS.addTrustedEntry(cacert.retrieveCertificate(), this.composeTrustAlias(tsInfo.getAlias(), certificateSubject));
                    }
                }
            }
        }
    }

    /**
     * clearTruststore
     * 
     * @param trustStoreInfo
     * @throws TrustHandlerException
     */
    public void clearTruststore(final TrustStoreInfo trustStoreInfo) throws TrustHandlerException {

        final String tsLocation = trustStoreInfo.getTrustFileLocation();
        final String tsAlias = trustStoreInfo.getAlias();
        final String tsPassword = trustStoreInfo.getTrustStorePwd();
        final TrustFormat tsType = trustStoreInfo.getCertFormat();
        final CredentialWriterFactory credWF = new CredentialWriterFactory();

        if (trustStoreInfo.isTrustFileLocationValid()) {
            try {
                // keyStore writer
                final CredentialWriter credWKS = credWF.getCredentialwriterInstanceForCert(StorageFormatUtils.getTrustFormatString(tsType), tsLocation, tsPassword);
                credWKS.deleteEntry(tsAlias);

            } catch (final StorageException e) {
                throw (new TrustHandlerException("deleteKeystoreEntry: " + e.getMessage()));
            }

            // check for empty file after deleting the entries 
            // (becuase if the file exists but its empty it can not be used by keytool)
            final File file = new File(tsLocation);
            if (file.length() == 0) {
                file.delete();
            }
        }

        // folder management
        if (trustStoreInfo.isTrustFolderValid()) {
            // use keystore delete method
            trustStoreInfo.removeFolderEntries();
        }

    } // end of deleteKeystoreEntry

    //
    //
    // this code can be used to delete the old certificate chain
    // if needed to replace it with a new one
    //
    //
    //    /**
    //     * clearKeystore
    //     * 
    //     * @param trustStoreInfo
    //     * @param keystoreInfo
    //     * @throws TrustHandlerException
    //     */
    //    private void clearKeystore(final KeystoreInfo keystoreInfo) throws TrustHandlerException {
    //
    //        final String ksLocation = keystoreInfo.getKeyAndCertLocation();
    //        final String ksAlias = keystoreInfo.getAlias();
    //        final String ksPassword = keystoreInfo.getKeyStorePwd();
    //        final CertificateFormat ksType = keystoreInfo.getCertFormat();
    //        final boolean flagAppend = true; // prima per cancellazione entry era false;
    //        final CredentialReaderFactory crf = new CredentialReaderFactory();
    //        final CredentialWriterFactory credWF = new CredentialWriterFactory();
    //        
    //        // 
    //        // this code reads the key and certificate from the given entry (alias) in the keystore,
    //        // delete the entry (in order to eliminate possible trust chain included in it)
    //        // and rewrite the same entry with key and cert
    //        //
    //        try {
    //
    //            final CredentialReader credRKS = crf.getCredentialreaderInstance(StorageFormatUtils.getCertFormatString(ksType), ksLocation, ksPassword);
    //
    //            // read the data
    //            final Key key = credRKS.getPrivateKey(ksAlias);
    //            final Certificate certificate = credRKS.getCertificate(ksAlias);
    //            if (certificate == null) {
    //            	LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_CERTIFICATE);
    //                throw (new TrustHandlerException("clearKeystore: error reading certificate"));
    //            }
    //            if (key == null) {
    //            	LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_KEY);
    //                throw (new TrustHandlerException("clearKeystore: error reading private key"));
    //            }
    //
    //            // keyStore writer
    //            final CredentialWriter credWKS = credWF.getCredentialwriterInstanceForCert(StorageFormatUtils.getCertFormatString(ksType), ksLocation, ksPassword, flagAppend);
    //            credWKS.deleteEntry(ksAlias);
    //
    //            // overwrite the same data (deleting the other possible trust chain)
    //            final Certificate[] chain = { certificate };
    //            credWKS.storeKeyPair(key, certificate, ksAlias, chain);
    //
    //        } catch (final StorageException e) {
    //            throw (new TrustHandlerException("clearKeystore: " + e.getMessage()));
    //        }
    //    } // end of clearKeystore

    private String composeTrustAlias(final String alias, final String subject) {
        String subjectForAlias = subject.replace(',', '_');
        subjectForAlias = subjectForAlias.replaceAll("\\s", "_"); //replace white spaces, in case files in folders have to be created
        subjectForAlias = subjectForAlias.replace("/", "_");//to avoid to read the subject first part as a folder
        return alias + "_" + subjectForAlias;
    }

} // end of class

