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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.pkcs.PKCS12SafeBag;
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

public class PKCS12Reader implements CredentialReader {

    private static final Logger LOG = LogManager.getLogger(PKCS12Reader.class);
    private String pkcs12FolderPath = "";
    private String pkcs12FilePath = "";
    private String password = "";
    // keystore type to use (PKCS12 or JCEKS)
    private String storeType = StorageConstants.PKCS12_STORE_TYPE;

    private PKCS12Reader() {

    }

    public PKCS12Reader(final String pkcs12FolderPath, final String pkcs12FilePath, final String password, final String storeType) {

        this();
        
        if (pkcs12FolderPath != null) {
            this.pkcs12FolderPath = pkcs12FolderPath;
        }
        if (pkcs12FilePath != null) {
            this.pkcs12FilePath = pkcs12FilePath;
        }
        if (password != null) {
            this.password = password;
        }
        if (StorageFormatUtils.isValidStorageConstant(storeType)) {
            this.storeType = storeType;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.nms.security.pki.store.CredentialReader#getCertificate(java .lang.String, java.lang.String, java.lang.String)
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
     * (non-Javadoc)final KeyStore keyStore = this.getKeyStore();
     * 
     * @see com.ericsson.nms.security.pki.store.CredentialReader#getPrivateKey(java .lang.String, java.lang.String, java.lang.String)
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
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificateChain(java.lang.String)
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
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#hasMoreEntries()
     */
    /*
     * 
     * @Override public boolean hasMoreEntries() throws StorageException {
     * 
     * final KeyStore keyStore; try { keyStore = this.getKeyStore(); } catch (StorageException e1) { LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_KS); // this means the file simple doent exist return
     * false; } try { return (keyStore.size() > 1); } catch (KeyStoreException e) { LOG.error(ErrorMsg.API_ERROR_STORAGE_GET_KSSIZE); throw new StorageException(e); } } // end of hasMoreEntries
     */

    /**
     * getKeyStore
     * 
     * @return
     * @throws StorageException
     */
    private KeyStore getKeyStore() throws StorageException {

        InputStream is = null;
        KeyStore keyStore = null;

        try {
            keyStore = KeyStore.getInstance(this.storeType);
            final File file = new File(this.pkcs12FilePath);
            is = new FileInputStream(file);
            keyStore.load(is, this.password.toCharArray());

        } catch (final FileNotFoundException e) {
            LOG.debug("File not found:" + this.pkcs12FilePath);
        } catch (final Exception ex) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_LOAD_KS, this.pkcs12FilePath, ex.getMessage());
            throw new StorageException(ex);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (final Exception ex) {
                    LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_INPUTSTREAM, this.pkcs12FilePath);
                    // No need to handle
                }
            }
        }
        return keyStore;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getAllCertificates()
     */
    @Override
    public Set<Certificate> getAllCertificates(final String rootAlias) throws StorageException {
        final PKCS12Writer writer = new PKCS12Writer();
        final Set<Certificate> certificates = new HashSet<Certificate>();

        // manage folder option
        if (this.pkcs12FolderPath != "") {
            //iterate for each file in the folder
            final File folder = new File(this.pkcs12FolderPath);
            if (folder.exists() && folder.isDirectory()) {
                for (final File file : folder.listFiles()) {
                    this.readCertificates(rootAlias, file.getPath(), writer, certificates);
                }
            }

        } else {
            this.readCertificates(rootAlias, this.pkcs12FilePath, writer, certificates);
        }
        return certificates;
    }

    /**
     * @param rootAlias
     * @param writer
     * @param certificates
     * @param filePath
     * @throws StorageException
     */
    private void readCertificates(final String rootAlias, final String filePath, final PKCS12Writer writer, final Set<Certificate> certificates) throws StorageException {
        final List<PKCS12SafeBag> storeBags = writer.loadBags(filePath);
        final Iterator<PKCS12SafeBag> iterator = storeBags.iterator();
        while (iterator.hasNext()) {
            final PKCS12SafeBag checkingBag = iterator.next();
            final String friendlyName = writer.readFriendlyName(checkingBag);
            if (friendlyName.startsWith(rootAlias)) {

                // extract the certificate
                Certificate certificate = null;

                final X509CertificateHolder certHldr = (X509CertificateHolder) checkingBag.getBagValue();
                final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                try {
                    certificate = converter.getCertificate(certHldr);
                } catch (final CertificateException e) {
                    LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_CERT, friendlyName);
                    throw new StorageException(e);
                }

                if (certificate != null) {
                    certificates.add(certificate);
                }
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCRLs(java.lang.String)
     */
    @Override
    public Set<CRL> getCRLs(final String alias) throws StorageException {
        // JKCS12 format doesnt allow CRL storage
        return null;
    }

} // end of PKCS12Reader
