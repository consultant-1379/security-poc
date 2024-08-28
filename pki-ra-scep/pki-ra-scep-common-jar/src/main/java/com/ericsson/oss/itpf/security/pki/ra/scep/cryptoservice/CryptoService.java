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
package com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.AliasNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreFileReaderException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;

/**
 * This class fetches the corresponding keyStoreFilePath,keyStoreFileType, password and alias name values for the requested caName from scepConfigurationListener and gets the certificate list from the
 * certificate chain.
 *
 * @author xtelsow
 */
public class CryptoService {

    @Inject
    private Logger logger;
    @Inject
    private ConfigurationListener configurationListener;
    @Inject
    private KeyStoreFileReaderFactory keyStoreFileReaderFactory;
    @Inject
    private SystemRecorder systemRecorder;

    private KeyStoreInfo keyStoreInfo;
    private KeyStoreFileReader keyStoreFileReader;

    /**
     * This method set the KeyStoreInfo with the configuration data fetched from configurationListener w.r.t the given alias name and the store type.
     *
     * @param aliasName
     *            is the alias name which is used to read content from key store file.
     * @param storeType
     *            type of the store (Key store/ Trust store).
     */
    private void setKeyStoreInfo(final String aliasName, final String storeType) throws PkiScepServiceException {
        try {
            final String password = System.getProperty("SCEP_RA_KEYSTORE_PASSWORD_PROPERTY");
            switch (storeType) {
            case Constants.STORE_TYPE_KEY_STORE:
                this.keyStoreInfo = new KeyStoreInfo(this.configurationListener.getKeyStoreFilePath(), KeyStoreType.valueOf(this.configurationListener.getKeyStoreFileType()), password, aliasName);
                break;
            case Constants.STORE_TYPE_TRUST_STORE:
                this.keyStoreInfo = new KeyStoreInfo(this.configurationListener.getScepRATrustStoreFilePath(), KeyStoreType.valueOf(this.configurationListener.getTrustStoreFileType()), password,
                        aliasName);
                break;
            default:
                logger.error("Invalid store type");
                systemRecorder.recordError("PKI_RA_SCEP.INVALID_KEY_STORE_TYPE", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                        "Invalid key store type observed during start up of scep client enrollment");
                throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
            }
        } catch (ConfigurationPropertyNotFoundException e) {
            logger.error("Model not configured properly");
            systemRecorder.recordError("PKI_RA_SCEP.MODEL_NOT_CONFIGURED", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollement and SCEP Client",
                    "KeyStore parameters are not configured properly");
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
    }

    /**
     * @return the keyStoreInfo
     */
    public KeyStoreInfo getKeyStoreInfo() {
        return keyStoreInfo;
    }

    /**
     * @param keyStoreInfo
     *            the keyStoreInfo to set
     */
    public void setKeyStoreInfo(final KeyStoreInfo keyStoreInfo) {
        this.keyStoreInfo = keyStoreInfo;
    }

    /**
     * This Method is used to get the certificate list from the certificate chain. Based on the length of the certificates it gets the certificates from chain and adds them to the Certificate List
     *
     * @param certificateChain
     *            chain of certificates from which the certificates will be retrieved.
     * @param isCompleteChain
     *            this says whether all the certificates from chain retrieved or not.
     *
     */
    public List<Certificate> getCertificateListFromChain(final Certificate[] certificateChain, final boolean isCompleteChain) {
        logger.debug("getCertificateListFromChain method in CryptoService class");
        int certLength = 2;

        if (isCompleteChain) {
            certLength = certificateChain.length;
        }

        final List<Certificate> certificateList = new ArrayList<>();
        for (int i = 0; i < certLength; i++) {
            certificateList.add(certificateChain[i]);
        }

        logger.debug("End of getCertificateListFromChain method in CryptoService class");
        return certificateList;
    }

    /**
     * readCertificateChain method will get the KeyStoreFileReader instance and then it will call getCertificateChainFromKeyStore method of KeyStoreFileReader to get the certificate chain form the key
     * store.
     *
     * @param caName
     *            is the alias name to get the certificate chain from key store.
     * @param isReadFromTrustStore
     *            boolean values which accepts true if certificate chain has to be read from trust store otherwise false.
     * @return Certificate Chain is the certificate chain read from the key store based on alias name.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown if any invalid response occurs
     */
    public Certificate[] readCertificateChain(final String caName, final boolean isReadFromTrustStore) throws PkiScepServiceException, BadRequestException {
        Certificate[] certChain = null;
        try {
            setKeyStoreFileReaderAndKeyStoreInfo(caName, isReadFromTrustStore);
            certChain = keyStoreFileReader.readCertificateChain(keyStoreInfo);
        } catch (final AliasNotFoundException e) {
            logger.error("Alias name not found with the given CA name");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_READER_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Alias Name is not found with the given CA Name :" + caName + " while reading Certificate chain from the Key Store");
            throw new BadRequestException(ErrorMessages.INVALID_CA_NAME);
        } catch (final KeyStoreFileReaderException e) {
            logger.error("Caught KeyStore Exception while fetching Certificate Chain from key store");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_READER_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Error occurred while fetching Certificate Chain from key store for CA Name :" + caName);
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
        logger.debug("End of readCertificateChain method in CryptoService class");
        return certChain;
    }

    /**
     * readCertificate method will get the KeyStoreFileReader instance and then it will call getCertificateFromKeyStore method of keyStoreFileReader to get the certificate from the keystore.
     *
     * @param caName
     *            is the alias name to get the certificate from key store.
     * @param isReadFromTrustStore
     *            boolean values which accepts true if certificate has to be read from trust store otherwise false.
     * @return Certificate is the certificate read from the key store based on alias name.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown when AliasNotFoundException occurs.
     */
    public Certificate readCertificate(final String caName, final boolean isReadFromTrustStore) throws PkiScepServiceException, BadRequestException {
        Certificate certificate = null;
        try {
            setKeyStoreFileReaderAndKeyStoreInfo(caName, isReadFromTrustStore);
            certificate = keyStoreFileReader.readCertificate(keyStoreInfo);
        } catch (final AliasNotFoundException e) {
            logger.error("Alias name not found with the given CA name");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_READER_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Alias Name is not found with the given CA Name :" + caName + " while reading Certificate from the Key Store");
            throw new BadRequestException(ErrorMessages.INVALID_CA_NAME);
        } catch (final KeyStoreFileReaderException e) {
            logger.error("Caught KeyStore Exception while fetching Certificate Chain from key store");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_READER_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Error occurred while fetching Certificate Chain from key store for CA Name :" + caName);
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
        logger.debug("End of readCertificate method in CryptoService class");
        return certificate;
    }

    /**
     * This method will read all the certificates from the key store of given storeType and return as a Set.
     * 
     * @param isReadFromTrustStore
     *            boolean values which accepts true if certificate has to be read from trust store otherwise false.
     * @return Set<X509Certificate> Set of certificates fetched from the key store of given storeType.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    public Set<X509Certificate> readAllCertificates(final boolean isReadFromTrustStore) throws PkiScepServiceException {

        setKeyStoreFileReaderAndKeyStoreInfo(null, isReadFromTrustStore);

        Set<X509Certificate> certificateSet = new HashSet<>();
        try {
            certificateSet = keyStoreFileReader.readCertificates(keyStoreInfo);
        } catch (KeyStoreException e) {
            logger.error("Caught KeyStore Exception while fetching Certificate Set from trust store");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_EXCEPTION", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Error occurred while fetching Certificate Set from trust store");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_READ_CERTS_FROM_TRUSTSTORE);
        }
        if (certificateSet.isEmpty()) {
            logger.error("No trust Certificates are found in the trust store");
            systemRecorder.recordError("PKI_RA_SCEP.NO_TRUST_CERTIFICATES", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "No trust Certificates are found in the trust store");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_READ_CERTS_FROM_TRUSTSTORE);
        }
        return certificateSet;
    }

    /**
     * readPrivateKey method will get the KeyStoreFileReader instance and then it will call getCertificateFromKeyStore method of KeyStoreFileReader to get the private key form the keystore.
     *
     * @param caName
     *            is the alias name to get the private key from key store.
     * @return PrivateKey is the private key read from the key store based on alias name.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             will be thrown when alias name not found with the given CA name
     */
    public PrivateKey readPrivateKey(final String caName) throws PkiScepServiceException, BadRequestException {
        PrivateKey privateKey = null;
        KeyStoreFileReader keyStoreFileReader = null;
        try {
            keyStoreFileReader = getKeystoreFileReaderInstance(caName);
            privateKey = keyStoreFileReader.readPrivateKey(keyStoreInfo);
        } catch (final AliasNotFoundException e) {
            logger.error("Alias name not found with the given CA name readPrivateKey");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_READER_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Alias Name is not found with the given CA Name :" + caName + " while reading Private key from the Key Store");
            throw new BadRequestException(ErrorMessages.INVALID_CA_NAME);
        } catch (final KeyStoreFileReaderException e) {
            logger.error("Caught KeyStore Exception while fetching private key from key store");
            systemRecorder.recordError("PKI_RA_SCEP.KEYSTORE_READER_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Error occured while fetching private key from key store for CA Name" + caName);
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
        logger.debug("End of readPrivateKey method in CryptoService class");
        return privateKey;
    }

    private void setKeyStoreFileReaderAndKeyStoreInfo(final String caName, final boolean isReadFromTrustStore) {
        if (isReadFromTrustStore) {
            setKeyStoreInfo(caName, Constants.STORE_TYPE_TRUST_STORE);
        } else {
            setKeyStoreInfo(caName, Constants.STORE_TYPE_KEY_STORE);
        }
        keyStoreFileReader = keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo);
        if (isReadFromTrustStore) {
            if (caName != null) {
                final List<String> aliases = keyStoreFileReader.getAllAliases(keyStoreInfo);
                for (String alias : aliases) {
                    if (alias.contains(caName.toLowerCase())) {
                        keyStoreInfo.setAliasName(alias);
                    }
                }
            }
        }
    }

    /**
     * getKeystoreFileReaderInstance calls the getKeyStoreFileReaderInstance to get the instance of keyStoreFileReader.
     *
     * @param caName
     *            is the alias name to get the certificate chain from key store.
     * @return KeyStoreFileReader is the instance of keystoreFileReader.
     */
    private KeyStoreFileReader getKeystoreFileReaderInstance(final String caName) {
        setKeyStoreInfo(caName, Constants.STORE_TYPE_KEY_STORE);
        KeyStoreFileReader keystoreFileReader = null;
        keystoreFileReader = keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo);
        return keystoreFileReader;
    }

}
