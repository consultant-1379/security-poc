/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;

public class CredMJKSWriter {

    private static final String STORE_TYPE = "JKS";

    private String jksFilePath = "";
    private String password = "";

    private KeyStore ks = null;

    private CredMJKSWriter() {

    }

    public CredMJKSWriter(final String jksFilePath, final String password) throws CredentialManagerStartupException {
        this();
        this.jksFilePath = jksFilePath;
        this.password = password;

        try {
            ks = KeyStore.getInstance(STORE_TYPE);
            final File file = new File(jksFilePath);
            if (file.exists()) {
                file.delete();
            }
        } catch (final Exception ex) {
            throw new CredentialManagerStartupException(ex);
        }

    }

    public void storeKeyPair(final Key key, final Certificate cert, final String alias, final Certificate[] certificateChain) throws CredentialManagerStartupException {

        // Store away the keystore.
        FileOutputStream fos = null;

        try {
            fos = createKeyStore(ks);

            // store new data
            ks.setKeyEntry(alias, key, password.toCharArray(), certificateChain);
            ks.store(fos, password.toCharArray());
        } catch (final Exception ex) {
            throw new CredentialManagerStartupException("Error creating keystore : " + jksFilePath, ex);
        } finally {
            try {
                if (fos != null) {
                    fos.flush();
                    fos.close();
                }
            } catch (final Exception ex) {
                throw new CredentialManagerStartupException("Error closing keystore : " + jksFilePath, ex);
            }
        }
    }

    private FileOutputStream createKeyStore(final KeyStore ks) throws IOException, NoSuchAlgorithmException, CertificateException, CredentialManagerStartupException, FileNotFoundException {
        FileOutputStream fos;
        final File file = new File(jksFilePath);
        if (!file.exists()) {
            file.createNewFile();
            ks.load(null, password.toCharArray());
        } else {
            throw new CredentialManagerStartupException("keystore already exist!");
        }
        fos = new FileOutputStream(file);
        return fos;
    }

    /**
     * @param ca
     * @throws CredentialManagerStartupException
     */
    public void addTrustedEntries(final Map<String, CredentialManagerCertificateAuthority> intCa, final Map<String, CredentialManagerCertificateAuthority> extCa, final String aliasPrefix)
            throws CredentialManagerStartupException {
        // Store away the keystore.
        FileOutputStream fos = null;

        try {
            fos = createKeyStore(ks);

            if (!intCa.isEmpty()) {
                addTrustToKeyStore(intCa, aliasPrefix);
            }

            if (!extCa.isEmpty()) {
                addTrustToKeyStore(extCa, aliasPrefix);
            }
            // store new data
            ks.store(fos, password.toCharArray());

        } catch (final Exception ex) {
            throw new CredentialManagerStartupException("Error creating keystore : " + jksFilePath, ex);
        } finally {

            try {
                if (fos != null) {
                    fos.flush();
                    fos.close();
                }

            } catch (final Exception ex) {
                throw new CredentialManagerStartupException("Error closing keystore : " + jksFilePath, ex);
            }
        }
    }

    /**
     * @param intCa
     * @param aliasPrefix
     * @throws KeyStoreException
     */
    private void addTrustToKeyStore(final Map<String, CredentialManagerCertificateAuthority> intCa, final String aliasPrefix) throws KeyStoreException {

        final Iterator<Entry<String, CredentialManagerCertificateAuthority>> iterator = intCa.entrySet().iterator();
        while (iterator.hasNext()) {
            final Entry<String, CredentialManagerCertificateAuthority> mapEntry = iterator.next();

            for (final CredentialManagerX509Certificate cacert : mapEntry.getValue().getCACertificateChain()) {
                final X509Certificate cert = cacert.retrieveCertificate();
                ks.setCertificateEntry(aliasPrefix + cert.getSubjectDN() + "_" + cert.getSerialNumber(), cert);
            }
        }
    }
}
