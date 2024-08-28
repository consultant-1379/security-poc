/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.storage.business;

import java.io.*;
import java.security.*;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

/**
 * 
 * @author esagchr Sarang Chalikwar
 * 
 */

public class JKSReader implements CredentialReader {

    private static final Logger LOG = LogManager.getLogger(JKSReader.class);

    private String jksFilePath = "";
    private String jksFolderPath = "";
    private String password = "";

    // keystore type to use (JKS or JCEKS)
    private String storeType = StorageConstants.JKS_STORE_TYPE;

    private JKSReader() {

    }

    public JKSReader(final String jksFolderPath, final String jksFilePath, final String password, final String storeType) {

        this();
        this.jksFolderPath = jksFolderPath;
        this.jksFilePath = jksFilePath;
        this.password = password;
        if (StorageFormatUtils.isValidStorageConstant(storeType)) {
            this.storeType = storeType;
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.ericsson.nms.security.pki.store.CredentialReader#getCertificate(java
     * .lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public Certificate getCertificate(final String alias) throws StorageException {

        final KeyStore keyStore = this.getKeyStore();
        try {
            return keyStore.getCertificate(alias);
        } catch (final KeyStoreException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_CERTIFICATE, alias);
            throw new StorageException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.ericsson.nms.security.pki.store.CredentialReader#getCertificate(java
     * .lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public Certificate[] getCertificateChain(final String alias) throws StorageException {

        final KeyStore keyStore = this.getKeyStore();
        try {
            return keyStore.getCertificateChain(alias);
        } catch (final KeyStoreException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_CERTCHAIN, alias);
            throw new StorageException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.ericsson.nms.security.pki.store.CredentialReader#getPrivateKey(java
     * .lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public Key getPrivateKey(final String alias) throws StorageException {

        final KeyStore keyStore = this.getKeyStore();
        try {
            return keyStore.getKey(alias, this.password.toCharArray());
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_PK, alias);
            throw new StorageException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader
     * #hasMoreEntries()
     */
    /*
     * @Override public boolean hasMoreEntries() throws StorageException {
     * 
     * final KeyStore keyStore; try { keyStore = this.getKeyStore(); } catch
     * (StorageException e1) { LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_KS); //
     * this means the file simple doent exist return false; } try { return
     * (keyStore.size() > 1); } catch (KeyStoreException e) {
     * LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_KSSIZE); throw new
     * StorageException(e); }
     * 
     * } // end of hasMoreEntries
     */

    /**
     * getKeyStore
     * 
     * @return
     * @throws StorageException
     */
    private KeyStore getKeyStore() throws StorageException {

        KeyStore keyStore = null;
        InputStream is = null;

        try {
            keyStore = KeyStore.getInstance(this.storeType);
            final File file = new File(this.jksFilePath);
            is = new FileInputStream(file);
            keyStore.load(is, this.password.toCharArray());

        } catch (final FileNotFoundException e) {
            LOG.debug("File not found:" + this.jksFilePath);
        } catch (final Exception ex) {
            LOG.debug(ErrorMsg.API_ERROR_STORAGE_LOAD_KS, this.jksFilePath, ex.getMessage());
            throw new StorageException(ex);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (final Exception ex) {
                    LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_INPUTSTREAM, this.jksFilePath);
                    // No need to handle
                }
            }
        }
        return keyStore;
    }

    @Override
    public Set<Certificate> getAllCertificates(final String rootAlias) throws StorageException {

        final Set<Certificate> certificates = new HashSet<Certificate>();
        try {
            // manage folder option
            if (this.jksFolderPath != "") {
                //iterate for each file in the folder
                final File folder = new File(this.jksFolderPath);
                if (folder.exists() && folder.isDirectory()) {
                    for (final File file : folder.listFiles()) {
                        // prepare a temporary filePath
                        this.jksFilePath = file.getPath();
                        // colleact the certificates for this file
                        this.readCertificates(rootAlias, certificates);
                        // reset filePath
                        this.jksFilePath = "";
                    }
                }
            } else {
                this.readCertificates(rootAlias, certificates);
            }
        } catch (StorageException | KeyStoreException e) {//TODO Convert print to log.Info()
            System.out.println("Checking JKS storage for " + rootAlias + ": not found");
            LOG.info("Checking JKS storage for " + rootAlias + ": not found");
            throw new StorageException(e);
        }
        return certificates;
    }

    /**
     * @param rootAlias
     * @param certificates
     * @throws StorageException
     * @throws KeyStoreException
     */
    private void readCertificates(final String rootAlias, Set<Certificate> certificates) throws StorageException, KeyStoreException {
        final KeyStore ks = this.getKeyStore();
        // Search for alias in the file
        final Enumeration<String> enumString = ks.aliases();
        while (enumString.hasMoreElements()) {
            final String element = enumString.nextElement();
            if (element.startsWith(rootAlias.toLowerCase())) {
                certificates.add(this.getCertificate(element));
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader
     * #getCRLs(java.lang.String)
     */
    @Override
    public Set<CRL> getCRLs(final String alias) throws StorageException {
        // JKS format doesnt allow CRL storage
        return null;
    }

} // end of JKSReader
