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
package com.ericsson.oss.itpf.security.pki.common.keystore;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * This Class is used for creating JKS/PKCS12 KeyStore file containing
 * Certificate(s).
 * 
 * @author xsrirko
 *
 */
public class CertificateKeyStoreFileBuilder {
    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateKeyStoreFileBuilder.class);

    /**
     * Method for Storing Certificates in KeyStore
     * 
     * @param certificates
     *            List of Certificates to be stored in KeyStore
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName.
     * @return Resource
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be
     *             loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore
     *             cannot be found
     * @throws NoSuchProviderException
     *             in case of Invalid Provider
     */
    public Resource createCertificateKeyStore(final List<Certificate> certificates, final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {
        LOGGER.debug("Creating keystore for storing certificates");
        final KeyStore keyStore = initializeKeyStore(keyStoreInfo);
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
        return Resources.getFileSystemResource(keyStoreFilePath);
    }

    /**
     * This method is used to Intialize KeyStore Object based on the
     * KeyStoreType(JKS/PKCS12) Provided
     * 
     * @param keyStoreInfo
     *            contains keystoreType, password, aliasName and filePath.
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be
     *             loaded
     * @throws IOException
     *             in case of KeyStore File is not proper
     * @throws KeyStoreException
     *             in case KeyStore generation fails
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore
     *             cannot be found
     */
    private KeyStore initializeKeyStore(final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {

        KeyStore keyStore = null;

        if (keyStoreInfo.getKeyStoreType().equals(KeyStoreType.PKCS12)) {

            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name(), new BouncyCastleProvider());

        } else {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
        }
        keyStore.load(null, null);

        return keyStore;
    }

}
