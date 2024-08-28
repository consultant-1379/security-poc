/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;
import javax.xml.datatype.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.*;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.InvalidDurationFormatException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.helper.CredentialsHelper;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.xml.model.StoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.EntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.EntityManagementLocalService;

/**
 * This class is used to get or generate credentials for pki-manager using the configuration data provided by PkiCredentialCertRequestXmlReader.
 * 
 * @author xnagsow
 *
 */
public class CredentialsManager {

    @Inject
    EntityCertificateManager entityCertificateManager;

    @Inject
    private PkiManagerCredentialsCertRequestXmlReader pkiCredentialCertRequestXmlReader;

    @Inject
    private CredentialsHelper credentialsHelper;

    @Inject
    private KeyStoreFileReader keyStorefileReader;

    @Inject
    private KeyStoreFileWriterFactory keyStoreFileWriterFactory;

    @Inject
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @EServiceRef
    private EntityManagementLocalService entityManagementLocalService;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    Logger logger;

    private static String keyStoreFilePath = null;
    private static String keyStorePassword = null;
    private static String trustStoreFilePath = null;
    private static String trustStorePassword = null;
    private static String entityName = null;
    private String subjectDN = null;
    private String entityProfileName = null;

    /**
     * This method will setup the credentials configuration data provided by the given pkimanagercredentialscertrequestxml file and then it will call the methods to generate the Credentials for the
     * PKI Manager.
     * 
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while getting or generating the credentials for pki-manager.
     */
    public void generatePkiCredentials() throws CredentialsManagementServiceException {
        logger.debug("generatePkiCredentials method of CredentialsManager");
        setupConfiguration();
        if (!(credentialsHelper.checkForFileExist(keyStoreFilePath) && credentialsHelper.checkForFileExist(trustStoreFilePath))) {
            credentialsHelper.createEntityIfNotExist(entityName, subjectDN, entityProfileName, getKeyGenAlgorithm());
            generateKeyStore();
            generateTrustStore();
        } else {
            final X509Certificate x509Certificate = getSignerCertificate();
            Duration overlapPeriod = null;
            try {
                overlapPeriod = convertStringToDuration(pkiCredentialCertRequestXmlReader.getOverlapPeriod());
                logger.debug("Overlap Period is: {}", overlapPeriod);
            } catch (final InvalidDurationFormatException e) {
                logger.debug("Exception occurred while converting String Date to duration ", e);
                logger.error("Exception occurred while converting String Date to duration {}", e.getMessage());
                systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.CERTIFICATE_EXPIRY_CHECK", "Improper overlapPeriod received from request xml ",
                        "PKI_CREDENTIALS_MANAGER.CERTIFICATE_EXPIRY_CHECKING", ErrorSeverity.CRITICAL, "FAILURE");
            }
            final Date expiryDate = x509Certificate.getNotAfter();
            if (overlapPeriod != null) {
                overlapPeriod.negate().addTo(expiryDate);
                if (expiryDate.compareTo(new Date()) <= 0) {
                    logger.debug("Generating key store and truststore since the certificate is expired");
                    generateKeyStore();
                    generateTrustStore();
                } else {
                    validateCertificateChain(x509Certificate);
                }
            }
        }
        logger.debug("End of generatePkiCredentials method of CredentialsManager");
    }

    /**
     * This method will generate and save the key store file if not exist at the given key store file path.
     * 
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while generating key store or saving the key store at the key store file path.
     */
    private void generateKeyStore() throws CredentialsManagementServiceException {
        final KeyStoreType keyStoreType = KeyStoreType.PKCS12;
        try {
            final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = entityCertificateManager.generateKeyStore(entityName,
                    keyStorePassword.toCharArray(), keyStoreType, RequestType.NEW);
            credentialsHelper.saveFile(keyStoreInfo.getKeyStoreFileData(), keyStoreFilePath);
        } catch (final AlgorithmNotFoundException | CertificateGenerationException | CertificateServiceException | ExpiredCertificateException | InvalidCAException | InvalidEntityException
                | KeyPairGenerationException | RevokedCertificateException e) {
            logger.error("Error while generating key store file for pki-manager credentials {}", e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.KeyStoreFileGenerator", "Error while generating key store file for pki-manager credentials",
                    "PKI_CREDENTIALS_MANAGER.KeyStoreFileGeneration", ErrorSeverity.CRITICAL, "FAILURE");
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        } catch (final EntityNotFoundException e) {
            logger.error("Error while generating key store file for pki-manager credentials {}", e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.KeyStoreFileGenerator", "Error while generating key store file for pki-manager credentials",
                    "PKI_CREDENTIALS_MANAGER.KeyStoreFileGeneration", ErrorSeverity.CRITICAL, "FAILURE");
            entityManagementLocalService.deletePkiManagerEntity(entityName);
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
    }

    /**
     * This method will generate and save the trust store file if not exist at the given trust store file path.
     * 
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while generating trust store or saving the trust store at the trust store file path.
     */
    private void generateTrustStore() throws CredentialsManagementServiceException {
        try {
            final List<Certificate> trustCertificateList = entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
            final KeyStoreInfo keyStoreInfo = new KeyStoreInfo(trustStoreFilePath, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS, trustStorePassword, entityName);
            keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo).createCertificateKeyStore(trustCertificateList, keyStoreInfo);
        } catch (final EntityNotFoundException | ProfileNotFoundException | CertificateServiceException | InvalidCAException | KeyStoreTypeNotSupportedException | CertificateException | KeyStoreException
                | NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
            logger.error("Error while generating trust store file for pki-manager credentials {}", e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.TrustStoreFileGenerator", "Error while generating trust store file for pki-manager credentials",
                    "PKI_CREDENTIALS_MANAGER.TrustStoreFileGeneration", ErrorSeverity.CRITICAL, "FAILURE");
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
    }

    private void setupConfiguration() throws CredentialsManagementServiceException {
        pkiCredentialCertRequestXmlReader.loadDataFromXML();
        String name = pkiCredentialCertRequestXmlReader.getSubjectType().getEntityName();
        entityName = credentialsHelper.resolveHostName(name);
        name = pkiCredentialCertRequestXmlReader.getSubjectType().getDistinguishName();
        subjectDN = credentialsHelper.resolveHostName(name);
        entityProfileName = pkiCredentialCertRequestXmlReader.getEndEntityProfileName();
        StoreType store = pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.PKCS12);
        keyStoreFilePath = store.getStoreLocation();
        keyStorePassword = store.getStorePassword();
        store = pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.JKS);
        trustStoreFilePath = store.getStoreLocation();
        trustStorePassword = store.getStorePassword();
    }

    private Algorithm getKeyGenAlgorithm() {
        final Algorithm keyGenerationAlgorithm = new Algorithm();
        keyGenerationAlgorithm.setKeySize(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairSize());
        keyGenerationAlgorithm.setName(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairAlgorithm());
        return keyGenerationAlgorithm;
    }

    /**
     * This method will return a set of trust certificates fetched from pki-manager trust store.
     *
     * @return Set<X509Certificate> trustCertificateSet
     * @throws CredentialsManagementServiceException
     *             is thrown when KeyStoreExeption occurs while reading certificates from trust store.
     */
    public Set<X509Certificate> getTrustCertificateSet() throws CredentialsManagementServiceException {
        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo(trustStoreFilePath, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS, trustStorePassword, entityName);
        try {
            return keyStorefileReader.readCertificates(keyStoreInfo);
        } catch (final KeyStoreException e) {
            logger.error("Error while reading certificates from trust store file {}", e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.GetTrustCertificates", "Error while reading certificates from trust store file",
                    "PKI_CREDENTIALS_MANAGER.readTrustCertificates", ErrorSeverity.CRITICAL, "FAILURE");
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
    }

    /**
     * This method will return private key fetched from pki-manager key store for the signer.
     *
     * @return PrivateKey signerPrivateKey
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while reading private key from key store.
     */
    public PrivateKey getSignerPrivateKey() throws CredentialsManagementServiceException {
        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo(keyStoreFilePath, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.PKCS12, keyStorePassword, entityName);
        try {
            return keyStorefileReader.readPrivateKey(keyStoreInfo);
        } catch (final AliasNotFoundException | InvalidKeyStoreDataException | KeyStoreNotLoadedException | CertificateNotLoadedException | PrivateKeyReaderException e) {
            logger.error("Error while reading private key from key store file {}", e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.GetSignerPrivateKey", "Error while reading private key from key store file",
                    "PKI_CREDENTIALS_MANAGER.readSignerPrivateKey", ErrorSeverity.CRITICAL, "FAILURE");
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
    }

    /**
     * This method will return signer certificate fetched from pki-manager key store for the signer.
     *
     * @return X509Certificate signerCertificate
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while reading certificate from key store.
     */
    public X509Certificate getSignerCertificate() throws CredentialsManagementServiceException {
        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo(keyStoreFilePath, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.PKCS12, keyStorePassword, entityName);
        try {
            return (X509Certificate) keyStorefileReader.readCertificate(keyStoreInfo);
        } catch (final AliasNotFoundException | com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException | InvalidKeyStoreDataException
                | KeyStoreNotLoadedException | CertificateNotLoadedException e) {
            logger.error("Error while reading certificate from key store file {}", e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.GetSignerCertificate", "Error while reading certificate from key store file",
                    "PKI_CREDENTIALS_MANAGER.GettingSignerCertificate", ErrorSeverity.CRITICAL, "FAILURE");
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
    }

    /**
     * This method will do chain validation for the given x509Certificate.If Chain validation failed for the given certificate then re generation of Key Store and Trust Store is initiated.
     *
     * @param X509Certificate
     *            x509Certificate Object
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while validating certificate chain.
     */
    private void validateCertificateChain(final X509Certificate x509Certificate) throws CredentialsManagementServiceException {
        logger.debug("Validating certificateChain for x509Certificate ");
        try {
            final Certificate certificate = certificatePersistenceHelper.getCertificate(x509Certificate);
            certificatePersistenceHelper.validateCertificateChain(certificate, EnumSet.of(CertificateStatus.REVOKED));
            logger.debug("Chain validation completed successfully ");
        } catch (final com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException | RevokedCertificateException e) {
            logger.debug("Certificate chain validation failed hence generating keyStore and trustStore files ", e);
            logger.error(e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_CREDENTIALS_MANAGER", "PKI_CREDENTIALS_MANAGER.CERTIFICATE_CHAIN_VALIDATOR",
                    "Certificate chain validation failed for Pki Credentials : Certificate Revoked ", "PKI_CREDENTIALS_MANAGER.CertificateChainValidation", ErrorSeverity.CRITICAL, "FAILURE");
            generateKeyStore();
            generateTrustStore();
        } catch (final CertificateServiceException e) {
            logger.error(e.getMessage());
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
    }

    /**
     * This method converts the String time representation to XML data type Duration
     *
     * @param timeAsString
     *            is the String representation of the time parameters.
     * @return XML data type duration notation of the String input
     * @throws InvalidDurationFormatException
     *             is thrown when failed to convert String to Duration.
     */
    // TODO: This method will be moved to pki-common as part of MS6 Bug fixes.Refactoring will be done once that goes to master.
    private Duration convertStringToDuration(final String timeAsString) throws InvalidDurationFormatException {
        if (timeAsString != null) {
            DatatypeFactory d = null;
            try {
                d = DatatypeFactory.newInstance();
                return d.newDuration(timeAsString);
            } catch (final DatatypeConfigurationException | IllegalArgumentException e) {
                logger.error("Failed to covert String to Duration");
                throw new InvalidDurationFormatException("Failed to covert String to Duration ", e);
            }
        }
        return null;
    }
}
