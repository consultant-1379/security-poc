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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;

/**
 * This class used to get the Certificate chain, Certificate and private key...etc from JKS/PKCS12 KeyStore.
 * 
 * @author xpranma
 * 
 */
public class KeyStoreFileWriterHelper {

    @Inject
    Logger logger;

    /**
     * This method loads keyStoreInfo data into KeyStore.
     * 
     * @param keyStoreInfo
     *            contains keystoreType, password, aliasName and filePath.
     * @param keyStoreFileData
     *            KeyStoreInfo data
     * @return KeyStore
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded.
     * @throws IOException
     *             in case of KeyStore File is not proper.
     * @throws KeyStoreException
     *             in case KeyStore generation fails.
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found.
     */
    public KeyStore loadKeyStoreWithData(final KeyStoreInfo keyStoreInfo, final byte[] keyStoreFileData) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {

        KeyStore ks = null;
        ByteArrayInputStream fis = null;
        try {
            ks = initializeKeyStore(keyStoreInfo);
            if (keyStoreFileData != null) {
                fis = new ByteArrayInputStream(keyStoreFileData);
            }
            ks.load(fis, keyStoreInfo.getPassword().toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        return ks;
    }

    /**
     * This method is used to initialize KeyStore Object based on the KeyStoreType(JKS/PKCS12) Provided
     * 
     * @param keyStoreInfo
     *            contains keystoreType, password, aliasName and filePath.
     * @throws CertificateException
     *             if any of the certificates in the KeyStore could not be loaded.
     * @throws IOException
     *             in case of KeyStore File is not proper.
     * @throws KeyStoreException
     *             in case KeyStore generation fails.
     * @throws NoSuchAlgorithmException
     *             if the algorithm used to check the integrity of the KeyStore cannot be found.
     */
    public KeyStore initializeKeyStore(final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {

        KeyStore keyStore = null;

        if (keyStoreInfo.getKeyStoreType().equals(KeyStoreType.PKCS12)) {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name(), new BouncyCastleProvider());

        } else {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
        }
        keyStore.load(null, null);

        return keyStore;
    }

    /**
     * Method to get temporary file to create keyStore
     * 
     * @param fileName
     *            name of the file to be created
     * @param fileExtension
     *            extension of the file
     * @return tempPath keyStore file path.
     */
    public String getTempFile(final String fileName, final String fileExtension) {
        return Constants.TMP_DIR + Constants.FILE_SEPARATOR + fileName + "." + fileExtension.toLowerCase();
    }

}
