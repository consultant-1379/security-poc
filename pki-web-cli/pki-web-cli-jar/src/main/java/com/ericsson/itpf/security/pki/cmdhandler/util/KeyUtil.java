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
package com.ericsson.itpf.security.pki.cmdhandler.util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * Utility to generate KeyStore
 * 
 * @author xsrirko
 * 
 */
public class KeyUtil {

    @Inject
    static Logger logger;

    static {

        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (SecurityException ex) {
            logger.warn("Cannot register BouncyCastleProvider", ex);
        }
    }

    /**
     * Method for Storing Certificates in KeyStore
     * 
     * @param certificates
     *            List of Certificates to be stored in KeyStore
     * @param keyStoreGenInfo
     *            Bean containing KeyStore Generation Data
     * @return 
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     */
    public String createCertificateKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {

        KeyStore keyStore = null;

        if (keyStoreInfo.getKeyStoreType().equals(KeyStoreType.PKCS12)) {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name(), BouncyCastleProvider.PROVIDER_NAME);
        } else {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
        }
        keyStore.load(null, null);
        int count = 1;
        for (final Certificate certificate : certificates) {
            keyStore.setCertificateEntry(keyStoreInfo.getAliasName() + count, certificate.getX509Certificate());
            count++;
        }
        final String keyStoreFilePath = keyStoreInfo.getFilePath();
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keyStoreFilePath);
            keyStore.store(fos, keyStoreInfo.getPassword().toCharArray());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
        return keyStoreFilePath;
    }

}
