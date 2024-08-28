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
import java.security.cert.CRL;
import java.util.*;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialWriterFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;

public class CrlHandler {

    private static final Logger LOG = LogManager.getLogger(CrlHandler.class);

    /**
     * getTrustCRLs
     * 
     * @param service
     * @param entityProfileName
     * @return
     * @throws TrustHandlerException
     */
    public CredentialManagerCrlMaps getTrustCRLs(final CredMServiceWrapper service, final String entityProfileName) throws TrustHandlerException {

        /**
         * Call getCRLs
         */
        if (service == null) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_WRAPPERNOTNULL, entityProfileName);
            throw (new TrustHandlerException("getTrustCRLs: service is NULL"));
        }
        System.out.println("getCrls for entity profile name: " + entityProfileName);
        LOG.info("getCrls for entity profile name: " + entityProfileName);
        CredentialManagerCrlMaps caMapCrl = null;
        try {
            caMapCrl = service.getCRLs(entityProfileName, CredentialManagerProfileType.ENTITY_PROFILE);
        } catch (final IssueCertificateException e) {
            throw (new TrustHandlerException("getTrustCRLs: service call exception"));
        }

        if (caMapCrl == null) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_CRLLIST);
            //System.out.println(" crl map empty ");
            throw (new TrustHandlerException("getTrustCRLs: caMapCrl is NULL"));
        }
        return caMapCrl;
    }

    /**
     * 
     * @param tsInfoList
     * @param caMapChain
     * @throws TrustHandlerException
     */
    public void writeTrustCRLs(final TrustStoreInfo tsInfo, final CredentialManagerCrlMaps caMapCrl) throws TrustHandlerException {
        try {
            if(caMapCrl == null){
                throw (new TrustHandlerException("writeTrustCRLs: crl maps cannot be null"));
            }
            final CredentialWriterFactory credWF = new CredentialWriterFactory();

            final String tsLocation = tsInfo.getTrustFileLocation();
            final String tsFolder = tsInfo.getTrustFolder();
            final TrustFormat tsType = tsInfo.getCertFormat();

            // TS writer
            final CredentialWriter credWTS = credWF.getCredentialwriterInstanceForCRL(StorageFormatUtils.getTrustFormatString(tsType), tsFolder, tsLocation);

            // CRL writing
            if (tsInfo.isTrustSourceInternalAndExternal()) {

                this.trustChainWrite(tsInfo, credWTS, caMapCrl.getInternalCACrlMap());
                this.trustChainWrite(tsInfo, credWTS, caMapCrl.getExternalCACrlMap());
            } else if (tsInfo.isTrustSourceInternal()) {
                this.trustChainWrite(tsInfo, credWTS, caMapCrl.getInternalCACrlMap());
            } else if (tsInfo.isTrustSourceExternal()) {
                this.trustChainWrite(tsInfo, credWTS, caMapCrl.getExternalCACrlMap());
            } else {
                throw (new TrustHandlerException("writeTrustCRLs: invalid source"));
            }

        } catch (final StorageException e) {
            throw (new TrustHandlerException("writeTrustCRLs: " + e.getMessage()));
        }
    }

    /**
     * @param tsInfo
     * @param credWTS
     * @param caMapChain
     * @throws StorageException
     */
    private void trustChainWrite(final TrustStoreInfo tsInfo, final CredentialWriter credWTS, final Map<String, CredentialManagerX509CRL> caMapCrl) throws StorageException {
        if (!caMapCrl.isEmpty()) {
            final Iterator<Entry<String, CredentialManagerX509CRL>> iterator = caMapCrl.entrySet().iterator();
            while (iterator.hasNext()) {
                final Entry<String, CredentialManagerX509CRL> mapEntry = iterator.next();
                final String subject = mapEntry.getKey();
                final CRL crl = mapEntry.getValue().retrieveCRL();

                /*
                 * LOG.debug("Entry from the chain: " + crl.toString());
                 */

                credWTS.addCrlEntry(crl, this.composeCrlAlias(tsInfo.getAlias(), subject));
            }
        }
    }

    /**
     * deleteCrlStore
     * 
     * @param csInfo
     * @param tsInfoList
     * @throws TrustHandlerException
     */
    public void clearCrlStore(final TrustStoreInfo csInfo) throws TrustHandlerException {

        final String tsLocation = csInfo.getTrustFileLocation();
        final String tsAlias = csInfo.getAlias();
        final String tsPassword = csInfo.getTrustStorePwd();
        final TrustFormat tsType = csInfo.getCertFormat();
        final CredentialWriterFactory credWF = new CredentialWriterFactory();

        if (csInfo.isTrustFileLocationValid()) {
            try {
                // keyStore writer
                final CredentialWriter credWKS = credWF.getCredentialwriterInstanceForCert(StorageFormatUtils.getTrustFormatString(tsType), tsLocation, tsPassword);
                credWKS.deleteEntry(tsAlias);

            } catch (final StorageException e) {
                throw (new TrustHandlerException("deleteKeystoreEntry: " + e.getMessage()));
            }

            /** check for empty file after deleting the entries 
            * (becuase if the file exists but its empty it can not be used by keytool)
            * not needed with .pem extension (base64 writer), cause the entire file is deleted
            * and not the single entry
            */
            final File file = new File(tsLocation);
            if (file.length() == 0) {
                file.delete();
            }
        }

        // folder management
        if (csInfo.isTrustFolderValid()) {
            // use keystore delete method
            csInfo.removeFolderEntries();
        }

    }

    private String composeCrlAlias(final String alias, final String subject) {
        return alias + "_" + subject.replace(",", "_");
    }

} // end of CrlHandler

