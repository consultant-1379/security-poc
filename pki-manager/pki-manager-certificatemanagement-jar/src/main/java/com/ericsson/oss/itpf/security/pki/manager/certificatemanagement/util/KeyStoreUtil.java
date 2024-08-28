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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;

/**
 * This class is used to load and store the certificate and key in KeyStore.
 */
public class KeyStoreUtil {

    @Inject
    Logger logger;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * load and store the certificate and key in KeyStore.
     * 
     * @param alias
     *            alias name for the private key
     * @param password
     *            password to protect the key.
     * @param keyStoreType
     *            the type of KeyStore.
     * @param keyPair
     *            keyPair contains private key.
     * @param certificateChain
     *            certificate chain certifying the corresponding public key.
     * @param entityName
     *            name of the entity.
     * @return fileName The file containing the KeyStore.
     * 
     * @throws CertificateGenerationException
     *             Thrown in case key store generation failures.
     */
    public String createKeyStore(final char[] password, final KeyStoreType keyStoreType, final KeyPair keyPair, final X509Certificate[] certificateChain, final String entityName)
            throws CertificateGenerationException {

        FileOutputStream out = null;
        java.security.KeyStore keyStore = null;
        String keyStoreFilePath = null;

        try {

            switch (keyStoreType) {
            case JKS:
                keyStore = java.security.KeyStore.getInstance(keyStoreType.value());
                keyStoreFilePath = Constants.TMP_DIR + Constants.FILE_SEPARATOR + entityName + Constants.JKS_EXTENSION;
                break;
            case PKCS12:
                keyStore = java.security.KeyStore.getInstance(keyStoreType.value(), new BouncyCastleProvider());

                keyStoreFilePath = Constants.TMP_DIR + Constants.FILE_SEPARATOR + entityName + Constants.P12_EXTENSION;
                break;
            default:
                logger.error("key store type {} is not supported", keyStoreType);
                throw new KeyStoreException(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID);
            }

            keyStore.load(null, password);

            out = new FileOutputStream(keyStoreFilePath);

            keyStore.setKeyEntry(entityName, keyPair.getPrivate(), password, certificateChain);
            keyStore.store(out, password);

        } catch (final CertificateException certificateException) {
            logger.error(ErrorMessages.CERTIFICATE_CHAIN_IS_NOT_PROPER, certificateException);
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_CHAIN_IS_NOT_PROPER + certificateException.getMessage());
        } catch (final FileNotFoundException fileNotFoundException) {
            logger.error(ErrorMessages.KEYSTORE_FILE_NOT_EXIST, fileNotFoundException);
            throw new CertificateGenerationException(ErrorMessages.KEYSTORE_FILE_NOT_EXIST + fileNotFoundException.getMessage());
        } catch (final IOException ioException) {
            logger.error(ErrorMessages.DATA_IS_NOT_PROPER + ioException);
            throw new CertificateGenerationException(ErrorMessages.DATA_IS_NOT_PROPER + ioException.getMessage());
        } catch (final KeyStoreException keyStoreException) {
            logger.error(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID, keyStoreException);
            throw new CertificateGenerationException(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID + keyStoreException.getMessage());
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
            throw new CertificateGenerationException(ErrorMessages.ALGORITHM_IS_NOT_FOUND + noSuchAlgorithmException.getMessage());
        } finally {
            closeOutStream(out);
        }
       return keyStoreFilePath;
    }

    private void closeOutStream(final FileOutputStream out){
            try {
                if (out != null) {
                    out.close();
                }

            } catch (IOException ioException) {
                throw new CertificateGenerationException(ErrorMessages.FILE_OUTPUT_IS_NOT_CLOSED + ioException.getMessage(), ioException);
            }

        }

    /**
     * Build KeyStroeInfo model with keyStore data.
     * 
     * @param password
     *            password of the key store.
     * @param alias
     *            alias of the private key and certificates.
     * @param keyStoreContent
     *            content of the key store generated.
     * @return KeyStoreInfo model that contains key store data, alias name and password of the key store.
     */
    public KeyStoreInfo buildKeyStoreInfoModel(final char[] password, final String alias, final byte[] keyStoreContent) {

        logger.info("Building key store info model with key store data");

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setPassword(password);
        keyStoreInfo.setAlias(alias);
        keyStoreInfo.setKeyStoreFileData(keyStoreContent);

        return keyStoreInfo;
    }
}
