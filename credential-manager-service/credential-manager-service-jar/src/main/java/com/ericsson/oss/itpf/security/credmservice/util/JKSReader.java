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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;


public class JKSReader {

    private String jksFilePath = "";
    private String password = "";
    private KeyStore keyStore = null;

    // keystore type to use (JKS or JCEKS)
    private String storeType = "JKS";

    @SuppressWarnings("unused")
    private JKSReader() {

    }

    public JKSReader(final String jksFilePath, final String password, final String storeType) {

        this.jksFilePath = jksFilePath;
        this.password = password;
        this.storeType = storeType;
    }

    public JKSReader(final InputStream is, final String password, final String storeType) {

        this.jksFilePath = null;
        this.password = password;
        this.storeType = storeType;
        try {
            keyStore = KeyStore.getInstance(this.storeType);
            keyStore.load(is, password.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * getKeyStore
     *
     * @return
     * @throws CredentialManagerStorageException
     */
    private KeyStore getKeyStore() {

        InputStream is = null;

        try {
            try {
                if (keyStore == null) {
                    keyStore = KeyStore.getInstance(this.storeType);
                    final File file = new File(this.jksFilePath);
                    is = new FileInputStream(file);
                    keyStore.load(is, password.toCharArray());
                    return keyStore;
                }
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (final Exception ex) {
                    // No need to handle
                }
            }
        }
        return keyStore;
    }

    public boolean isAliasPresent(final String aliasName) {

        try {
            return getKeyStore().isKeyEntry(aliasName);
        } catch (final KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }

    public Certificate getCertificate(final String aliasName) {
        try {
            return keyStore.getCertificate(aliasName);
        } catch (final KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public List<Certificate> getAllCertificates() {
        final List<Certificate> ret = new ArrayList<Certificate>();
        try {
            final Enumeration<String> aliases = getKeyStore().aliases();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                ret.add(keyStore.getCertificate(alias));
            }
        } catch (final KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return ret;
    }
}
