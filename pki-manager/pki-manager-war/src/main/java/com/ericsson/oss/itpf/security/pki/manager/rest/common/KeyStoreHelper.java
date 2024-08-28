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
package com.ericsson.oss.itpf.security.pki.manager.rest.common;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.*;
import static com.ericsson.oss.itpf.security.pki.manager.rest.util.ErrorMessages.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.CertificateRequestDTO;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * Helper class for CertificateKeyStoreFileBuilder
 * 
 * @author tcsrcho
 *
 */
public class KeyStoreHelper {

    @Inject
    KeyStoreFileWriterFactory keyStoreFileWriterFactory;

    @Inject
    KeyStoreFileWriterHelper keyStoreFileWriterHelper;

    @Inject
    FileUtility fileUtility;
    @Inject
    Logger logger;

    /**
     * creates KeyStoreInfo.
     * 
     * @param fileName
     *            Certificate fileName.
     * @param format
     *            KeyStore type/extension.
     * @param password
     *            password to store certificate in KeyStore.
     * @param alias
     *            alias name to get the certificate from KeyStore.
     * @return KeyStoreInfo KeyStoreInfo contains file path, format, password and alias name.
     */
    public KeyStoreInfo createKeyStoreInfo(final String fileName, final KeyStoreType format, final String password, final String alias) {

        final String filePath = keyStoreFileWriterHelper.getTempFile(fileName, format.value());
        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo(filePath, format, password, alias);
        return keyStoreInfo;

    }

    /**
     * This method prepares KeyStoreInfo object and creates KeyStore for certificates.
     * 
     * @param keyStoreInfo
     *            keyStoreInfo contains alias name, keyStore type and password.
     * @param certificates
     *            list of certificates
     * @return name of the resource , KeyStore file contains list of certificates with the given type/extension.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    public String createKeyStore(final KeyStoreInfo keyStoreInfo, final List<Certificate> certificates) throws CertificateServiceException {
        String resourceName = null;

        try {

            resourceName = keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo).createCertKeyStore(certificates, keyStoreInfo);
            logger.debug("Successfully generated Certificate {}", resourceName);

        } catch (CertificateException certificateException) {
            logger.error(CERTIFICATE_IS_NOT_LOADED, certificateException);
            throw new CertificateServiceException(CERTIFICATE_IS_NOT_LOADED + certificateException.getMessage());
        } catch (IOException ioException) {
            logger.error(ErrorMessages.DATA_IS_NOT_PROPER + ioException);
            throw new CertificateServiceException(ErrorMessages.DATA_IS_NOT_PROPER + ioException.getMessage());
        } catch (KeyStoreException keyStoreException) {
            logger.error(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID, keyStoreException);
            throw new CertificateServiceException(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID + keyStoreException.getMessage());
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(KEYSTORE_ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
            throw new CertificateServiceException(KEYSTORE_ALGORITHM_IS_NOT_FOUND + noSuchAlgorithmException.getMessage());
        } catch (NoSuchProviderException noSuchProviderException) {
            logger.error(PROVIDER_IS_NOT_AVAILABLE, noSuchProviderException);
            throw new CertificateServiceException(PROVIDER_IS_NOT_AVAILABLE + noSuchProviderException.getMessage());
        }

        return resourceName;
    }

    /**
     * This method loads keyStoreInfo data into KeyStore.
     * 
     * @param keyStoreInfo
     *            contains keystoreType, password, aliasName and filePath.
     * @param keyStoreFileData
     *            KeyStoreInfo data
     * @return name of the resource , KeyStore file contains certificates with the given type/extension.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    public String loadAndStoreKeyStore(final String password, final KeyStoreInfo KeyStoreInfo,
            final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData) throws CertificateServiceException {

        FileOutputStream fos = null;
        String resourceName = null;
        try {

            final String keyStoreFilePath = KeyStoreInfo.getFilePath();
            fos = new FileOutputStream(keyStoreFilePath);
            resourceName = fileUtility.getFileNameFromAbsolutePath(keyStoreFilePath);

            final KeyStore ks = keyStoreFileWriterHelper.loadKeyStoreWithData(KeyStoreInfo, keyStoreInfoData.getKeyStoreFileData());
            ks.store(fos, password.toCharArray());

        } catch (CertificateException certificateException) {
            logger.error(CERTIFICATE_IS_NOT_LOADED, certificateException);
            throw new CertificateServiceException(CERTIFICATE_IS_NOT_LOADED + certificateException.getMessage());
        } catch (KeyStoreException keyStoreException) {
            logger.error(KEYSTORE_TYPE_IS_NOT_VALID, keyStoreException);
            throw new CertificateServiceException(KEYSTORE_TYPE_IS_NOT_VALID + keyStoreException.getMessage());
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(KEYSTORE_ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
            throw new CertificateServiceException(KEYSTORE_ALGORITHM_IS_NOT_FOUND + noSuchAlgorithmException.getMessage());
        } catch (IOException ioException) {
            logger.error(DATA_IS_NOT_PROPER + ioException);
            throw new CertificateServiceException(DATA_IS_NOT_PROPER + ioException.getMessage());
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (final IOException ioException) {
                logger.debug("Error occured while closing the file ", ioException);
                logger.error(FILE_OUTPUT_IS_NOT_CLOSED + ioException.getMessage());
            }
        }

        return resourceName;
    }

    /**
     * Method to add certificate chain into KeyStore along with private key and certificates. If private key is not available then certificates are added directly.
     * 
     * @param keyStoreInfo
     *            KeyStoreInfo that contains information of end entity certificate
     * @param certificateRequestDTO
     *            object containing all the required fields to issue certificate/s through REST
     * @param certificateChain
     *            contains list of certificates from specified entity to rootCA.
     * @param keyStoreFileData
     *            certificate data along with its private key
     * @return name of the resource , KeyStore file contains certificates with the given type/extension.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    public String buildKeyStoreWithCertificateChain(final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo,
            final CertificateRequestDTO certificateRequestDTO, final CertificateChain certificateChain) throws CertificateServiceException {

        String resourceName = null;
        List<Certificate> certificates = new ArrayList<Certificate>();

        try {
            certificates = certificateChain.getCertificates();
            final KeyStoreInfo commonKeyStoreInfo = createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(),
                    certificateRequestDTO.getName());
            resourceName = keyStoreFileWriterFactory.getKeystoreFileWriterInstance(commonKeyStoreInfo).addCertChainToKeyStore(certificates, commonKeyStoreInfo, keyStoreInfo.getKeyStoreFileData());

        } catch (CertificateException certificateException) {
            logger.error(CERTIFICATE_IS_NOT_LOADED, certificateException);
            throw new CertificateServiceException(CERTIFICATE_IS_NOT_LOADED + certificateException.getMessage());
        } catch (IOException ioException) {
            logger.error(ErrorMessages.DATA_IS_NOT_PROPER + ioException);
            throw new CertificateServiceException(ErrorMessages.DATA_IS_NOT_PROPER + ioException.getMessage());
        } catch (KeyStoreException keyStoreException) {
            logger.error(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID, keyStoreException);
            throw new CertificateServiceException(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID + keyStoreException.getMessage());
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(KEYSTORE_ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
            throw new CertificateServiceException(KEYSTORE_ALGORITHM_IS_NOT_FOUND + noSuchAlgorithmException.getMessage());
        } catch (UnrecoverableKeyException unrecoverableKeyException) {
            logger.error(UNRECOVERABLE_KEY, unrecoverableKeyException);
            throw new CertificateServiceException(UNRECOVERABLE_KEY + unrecoverableKeyException.getMessage());
        } catch (NoSuchProviderException noSuchProviderException) {
            logger.error(PROVIDER_IS_NOT_AVAILABLE, noSuchProviderException);
            throw new CertificateServiceException(PROVIDER_IS_NOT_AVAILABLE + noSuchProviderException.getMessage());
        }

        return resourceName;
    }

}
