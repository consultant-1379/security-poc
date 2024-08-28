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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.security.cert.*;
import java.util.*;

import javax.inject.Inject;
import javax.naming.InvalidNameException;
import javax.persistence.*;

import org.bouncycastle.cert.CertException;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;

/**
 * This Helper class provides methods that help in retrieving and storing various Certificate related data.
 * 
 */
public class CertificatePersistenceHelper {

    // TODO: This class needs to be modified. User story reference : TORF-54827

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    DateUtil dateUtil;

    @Inject
    CertificateGenerationInfoParser certificateGenerationInfoParser;

    @Inject
    private SystemRecorder systemRecorder;

    private static final String NAME = "name";
    private static final String ALGORITHM_KEY_SIZE = "keySize";
    private static final String ALGORITHM_TYPE = "type";
    // TODO: Configuration of DB queries will be analyzed as part of the spike TORF-83179
    private static final String updateCertStatusToExpiredQuery = "UPDATE  CertificateData c SET  c.status=(:status) WHERE c.notAfter < (:currDate) AND c.status in (:certStatus)";
    private static final String ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS = "select c from CertificateData c where c.status in(:statusList) and c.id in(select p.id from EntityInfoData ec inner join ec.certificateDatas p  WHERE ec.name = :name) ORDER BY c.id DESC";

    /**
     * Retrieves the {@link CertificateAuthorityData} by building a criteria query from CA name
     * 
     * @param cAName
     *            name of CA
     * @return CertificateAuthorityData retrieved from database
     * @throws CoreEntityNotFoundException
     *             Thrown in case given CA not found in the database.
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     */
    public CertificateAuthorityData getCA(final String cAName) throws CoreEntityNotFoundException, CoreEntityServiceException {

        logger.debug("Getting Certificate authority data for CA : {} ", cAName);
        final List<CertificateAuthorityData> certificateAuthorityDatas = getEntities(cAName, CertificateAuthorityData.class);
        if (!certificateAuthorityDatas.isEmpty()) {
            return certificateAuthorityDatas.get(0);
        } else {
            logger.error("{} : {}", cAName, ErrorMessages.CERTIFICATE_AUTHORITY_NOT_FOUND);
            systemRecorder.recordError("PKICORE.GETCA", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CA Entity", "CA " + cAName
                    + " does not exist in PKI System");
            throw new CoreEntityNotFoundException(ErrorMessages.CERTIFICATE_AUTHORITY_NOT_FOUND);
        }
    }

    /**
     * Retrieves the {@link EntityInfoData} by building a criteria query from entity name
     * 
     * @param entityName
     *            name of Entity.
     * @return EntityData retrieved from database
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     */
    public EntityInfoData getEntityData(final String entityName) throws CoreEntityServiceException {

        final List<EntityInfoData> entityDatas = getEntities(entityName, EntityInfoData.class);
        if (!entityDatas.isEmpty()) {
            return entityDatas.get(0);
        }
        return null;
    }

    private <T> List<T> getEntities(final String entityName, final Class<T> entityClass) throws CoreEntityServiceException {

        logger.debug("Fetching Entites using entity name : {} ", entityName);
        final HashMap<String, Object> parameters = new HashMap<>();
        parameters.put(NAME, entityName);
        try {
        return persistenceManager.findEntitiesByAttributes(entityClass, parameters);
        } catch (PersistenceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR + "for" + entityName);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CA Entity",
                    "Error occured while fetching Entity: " + entityName);
            throw new CoreEntityServiceException(exception.getMessage(), exception);
        }

    }

    /**
     * Updates CertificateRequestData with status and CertificatData in Database
     *
     * @param certificateRequestData
     *            the CertificateRequest that needs to be updated
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     */
    public void updateCSR(final CertificateRequestData certificateRequestData) throws CertificateServiceException {
        logger.debug("Updating CSR Info ");
        certificateRequestData.setStatus(CertificateRequestStatus.ISSUED.getId());
        try {
            persistenceManager.updateEntity(certificateRequestData);
        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificateRequestPersistenceHandler",
                    "CertificateRequestData", "Error occured while updating the database entity");
            throw new CertificateServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, exception);
        }
    }

    /**
     * Saves Entity information in the database and returns the saved entity.
     *
     * @param entityData
     *
     * @return EntityData saved in the database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case if entity already exists in database.
     */
    public EntityInfoData storeAndReturnEntityData(final EntityInfoData entityData) throws CoreEntityAlreadyExistsException {

        logger.debug("Saving entity information : {} in the database", entityData.getName());
        try {
            persistenceManager.createEntity(entityData);
            return entityData;
        } catch (javax.persistence.EntityExistsException entityExistsException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(entityData.getName() +" : "+ ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE, entityExistsException);
            throw new CoreEntityAlreadyExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE);
        }
    }

    /**
     * Saves the certificate generated and updates CA entity or Entity with the certificate generated for it.
     * 
     * @param certificate
     *            certificate generated for CA entity or Entity.
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} which has CA entity or Entity.
     * @param certificateAuthorityData
     * @param issuerData
     * @param keyIdentifierData
     * @return CertificateData
     * @throws CertificateGenerationException
     *             Throws in case any failures occur when reading certificate.
     * @throws CertificateExistsException
     *             Thrown in case of certificate entity already exists in the database.
     * @throws InvalidCertificateException
     *             Thrown in case of certificate data is corrupted.
     */
    public CertificateData storeAndReturnCertificate(final X509Certificate certificate, final CertificateGenerationInfo certificateGenerationInfo,
            final CertificateAuthorityData certificateAuthorityData, final CertificateAuthorityData issuerData, final KeyIdentifierData keyIdentifierData) throws CertificateGenerationException,
            InvalidCertificateException {

        try {
            logger.debug("Storing Certificate to the database {} ", certificate.getSubjectDN());
            final CertificateData certificateData = new CertificateData();
            certificateData.setSerialNumber(certificate.getSerialNumber().toString(16));
            certificateData.setCertificate(certificate.getEncoded());
            certificateData.setNotBefore(certificate.getNotBefore());
            certificateData.setNotAfter(certificate.getNotAfter());
            certificateData.setIssuedTime(certificate.getNotBefore());
            certificateData.setStatus(CertificateStatus.ACTIVE);
            certificateData.setRevokedTime(null);
            certificateData.setSubjectDN(certificateGenerationInfoParser.getSubjectDNFromCertGenerationInfo(certificateGenerationInfo));
            certificateData.setSubjectAltName(JsonUtil.getJsonFromObject(certificateGenerationInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)));

            if (issuerData != null) {
                certificateData.setIssuerCA(issuerData);
                final Set<CertificateData> issuerCertificatesData = issuerData.getCertificateDatas();
                for (final CertificateData issuerCertificateData : issuerCertificatesData) {
                    if (issuerCertificateData.getStatus() == CertificateStatus.ACTIVE) {
                        certificateData.setIssuerCertificate(issuerCertificateData);
                        break;
                    }
                }
            } else {
                logger.info("Issuer data is null for: {}", certificateGenerationInfo.getCAEntityInfo().getName());
                certificateData.setIssuerCA(certificateAuthorityData);
                final Set<CertificateData> issuerCertificatesData = certificateAuthorityData.getCertificateDatas();
                for (final CertificateData issuerCertificateData : issuerCertificatesData) {
                    if (issuerCertificateData.getStatus() == CertificateStatus.ACTIVE) {
                        certificateData.setIssuerCertificate(issuerCertificateData);
                        break;
                    }
                }
            }
            certificateData.setKeyIdentifier(keyIdentifierData);
            // persistenceManager.createEntity(certificateData);

            logger.info("CertificateData stored in PKI Core database.");
            return certificateData;

        } catch (CertificateEncodingException certificateEncodingException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, certificateEncodingException);
            throw new InvalidCertificateException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION);
        }

    }

    /**
     * This method stores the certificate and maps corresponding key identifier to it.
     * 
     * @param certificate
     *            Certificate info to be stored
     * @param keyIdentifierData
     *            Key Identifier Data
     * @return certificate Data
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * @throws InvalidCertificateException
     *             Thrown when Invalid certificate is found
     *
     *
     */
    public CertificateData storeAndReturnCertificate(final X509Certificate certificate, final KeyIdentifierData keyIdentifierData) throws CertificateServiceException, InvalidCertificateException {

        try {
            logger.debug("Storing Certificate to the database with DN: {} and serial number: {} ", certificate.getSubjectDN(), certificate.getSerialNumber());
            final CertificateData certificateData = new CertificateData();
            certificateData.setSerialNumber(certificate.getSerialNumber().toString(16));
            certificateData.setCertificate(certificate.getEncoded());
            certificateData.setNotBefore(certificate.getNotBefore());
            certificateData.setNotAfter(certificate.getNotAfter());
            certificateData.setIssuedTime(certificate.getNotBefore());
            certificateData.setStatus(CertificateStatus.ACTIVE);
            certificateData.setRevokedTime(null);
            // Bouncycastle reverses SubjectDN and IssuerDN while issuing certificates.As a result IssuerDN in sub CA certificates does not match with SubjectDN of imported ExtenalCA signed PKI
            // RootCA.
            // To prevent this as a work around, SubjectDN is reversed and stored in Certificate table for the imported certificate. This change is done as part of TORF-139992
            certificateData.setSubjectDN(CertificateUtility.getReversedSubjectDN(certificate.getSubjectDN().toString()));
            certificateData.setSubjectAltName(JsonUtil.getJsonFromObject(CertificateUtility.getSANFromCertificate(certificate)));

            certificateData.setKeyIdentifier(keyIdentifierData);
            persistenceManager.createEntity(certificateData);

            logger.info("CertificateData stored in PKI Core database. {}", certificate.getSubjectDN());
            systemRecorder.recordSecurityEvent("PKICore.CertificateManagement", "CertificatePersistenceHelper",
                    "CertificateData stored in PKI Core database with subject DN "+ certificate.getSubjectDN().toString(), "PKICore.StoreAndReturnCertificate", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            return certificateData;

        } catch (CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, certificateEncodingException.getMessage());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CertificateData",
                    "Invalid encoding of certificate with DN: " + certificate.getSubjectDN().toString() + " Serial number: " + certificate.getSerialNumber());
            throw new InvalidCertificateException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, certificateEncodingException);
        } catch (CertificateParsingException certificateParsingException) {
            logger.error(ErrorMessages.CERTIFICATE_EXCEPTION, certificateParsingException.getMessage());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CertificateData",
                     "Error parsing certificate to get the extension with DN : " + certificate.getSubjectDN().toString() + " Serial number: "+ certificate.getSerialNumber());
            throw new InvalidCertificateException(ErrorMessages.CERTIFICATE_EXCEPTION, certificateParsingException);
        } catch (InvalidNameException invalidNameException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, invalidNameException.getMessage());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CertificateData",
                    "Invalid Naming exception for certificate with subject DN : " + certificate.getSubjectDN().toString() + " Serial number: " + certificate.getSerialNumber());
            throw new InvalidCertificateException(ErrorMessages.CERTIFICATE_EXCEPTION, invalidNameException);
        } catch (EntityExistsException entityExistsException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, entityExistsException.getMessage());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CertificateData",
                    "Entity already exist in database for certificate with subject DN : " + certificate.getSubjectDN().toString() + " Serial number: " + certificate.getSerialNumber());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, entityExistsException);
        } catch (TransactionRequiredException transactionRequiredException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, transactionRequiredException.getMessage());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CertificateData",
                    "Transaction needed for this operation to store certificate with subject DN : " + certificate.getSubjectDN().toString() + " Serial number: " + certificate.getSerialNumber());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, transactionRequiredException);
        }
    }

    /**
     * Saves the CA entity in the database and returns the same.
     *
     * @param certificateAuthorityData
     *            {@link CertificateGenerationInfo} which has information about CA Entity.
     * @return CertificateAuthorityData saved in the database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case of CA entity already exists in database.
     */
    public CertificateAuthorityData storeAndReturnCertificateAuthority(final CertificateAuthorityData certificateAuthorityData) throws CoreEntityAlreadyExistsException {

        try {
            logger.debug("Stroing Certificate Authority data in the database ");
            persistenceManager.createEntity(certificateAuthorityData);
            logger.debug("Successfully stored Certificate Authority data in the database {} ", certificateAuthorityData);
            return certificateAuthorityData;

        } catch (javax.persistence.EntityExistsException entityExistsException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE, entityExistsException);
            throw new CoreEntityAlreadyExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE);
        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_STORING_DATABASE);
            throw new CertificateServiceException(ErrorMessages.ERROR_OCCURED_IN_STORING_DATABASE, exception);
        }
    }

    /**
     * Updates the CA Entity with active certificate and make old certificate to inactive.
     * 
     * @param certificateData
     *            Certificate to be mapped with CertificateAuthority.
     * @param certificateAuthorityData
     *            CertificateAuthority to be updated with new Certificate.
     * @param issuerCAData
     * @param cAStatus
     * @throws CoreEntityNotFoundException
     *             Thrown when entity is not found in the system.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while updating the CA certificate status.
     */
    public void updateCAWithActiveCertificate(final CertificateData certificateData, final CertificateAuthorityData certificateAuthorityData, final CertificateAuthorityData issuerCAData,
            final CAStatus cAStatus) throws CertificateServiceException, CoreEntityNotFoundException {

        logger.debug("Updating CA having Subject DN {} and Serial number {} with Active Certificate", certificateData.getSubjectDN(), certificateData.getSerialNumber());
        final CertificateAuthorityData cerAuthorityData = makeCACertificateInActive(certificateAuthorityData);

        try {
            cerAuthorityData.getCertificateDatas().add(certificateData);
            cerAuthorityData.setStatus(cAStatus);

            if (certificateAuthorityData.isRootCA()) {
                certificateAuthorityData.setIssuerCA(certificateAuthorityData);
            } else {
                certificateAuthorityData.setIssuerCA(issuerCAData);
            }

            final Set<CrlGenerationInfoData> crlGenerationInfoDataSet = certificateAuthorityData.getCrlGenerationInfo();
            for (final CrlGenerationInfoData crlGenerationInfoData : crlGenerationInfoDataSet) {
                crlGenerationInfoData.getCaCertificate().add(certificateData);
            }
            persistenceManager.createEntity(certificateData);
            persistenceManager.refresh(certificateAuthorityData);
            persistenceManager.updateEntity(certificateAuthorityData);

        } catch (javax.persistence.EntityNotFoundException entityNotException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, entityNotException);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper",
                    "CertificateAuthorityData", "Entity not found in database for certificate with subject DN :  " + certificateData.getSubjectDN());
            throw new CoreEntityNotFoundException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE);
        } catch (javax.persistence.EntityExistsException entityExistsException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE, entityExistsException);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper",
                    "CertificateAuthorityData", "Entity already exists in database with subject DN: " + certificateData.getSubjectDN());
            throw new CoreEntityAlreadyExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE);
        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper",
                    "CertificateAuthorityData", "Error occured in updating the database entity " + certificateData.getSubjectDN());
            throw new CertificateServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, exception);
        }

        systemRecorder.recordSecurityEvent("PKICore.CertificateManagement", "CertificatePersistenceHelper", "Updating CA " + certificateAuthorityData.getName()
                + "with active certificate [serial number = " + certificateData.getSerialNumber() + "]", "CERTIFICATEMANAGEMENT.STORE_CA_CERTIFICATE_CORE_DB", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    /**
     * Updates the CA Entity with active keys and make old keys to inactive
     *
     * @param certificateAuthorityData
     *            certificateAuthorityData to be updated with active keys.
     * @param keyData
     *            keyData to be added to certificateAuthorityData.
     * @throws CertificateServiceException
     *             thrown for any certificate related database errors in PKI Core.
     */
    public void updateCAWithActiveKeys(final CertificateAuthorityData certificateAuthorityData, final KeyIdentifierData keyData) throws CertificateServiceException {

        logger.debug("Updating CA {} with active keys", certificateAuthorityData.getName());
        try {
            final Set<KeyIdentifierData> cAKeys = new HashSet<KeyIdentifierData>();
            cAKeys.add(keyData);

            certificateAuthorityData.setcAKeys(cAKeys);
            persistenceManager.updateEntity(certificateAuthorityData);

        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE);
            throw new CertificateServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, exception);
        }
        systemRecorder.recordSecurityEvent("PKICore.CertificateManagement", "CertificatePersistenceHelper", "Updating CA with active keys ",
                "CERTIFICATEMANAGEMENT.UPDATE_CA_KEYS", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    /**
     * Updates the Entity in the database with new certificate generated and its corresponding CSR.
     *
     * @param certificateData
     *            Certificate to be mapped with Entity.
     * @param entityData
     *            EntityData to be updated with new Certificate.
     * @param issuer
     * @param entityStatus
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     * 
     */
    public void updateEntityData(final CertificateData certificateData, final EntityInfoData entityData, final CertificateAuthorityData issuer, final EntityStatus entityStatus)
            throws CoreEntityServiceException {

        try {
            final EntityInfoData enData = makeEntityCertificateInActive(entityData);
            persistenceManager.createEntity(certificateData);

            entityData.getCertificateDatas().add(certificateData);
            enData.setStatus(entityStatus);
            enData.setIssuerCA(issuer);

            persistenceManager.updateEntity(enData);
        } catch (javax.persistence.EntityNotFoundException entityNotException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, entityNotException);
            throw new CoreEntityAlreadyExistsException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE);
        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE);
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, exception);
        }
    }

    /**
     * Gets the decrypted issuer private key from the database.
     * 
     * @param cAName
     *            CA Name whose key Id to be retrieved from Database.
     * @throws CoreEntityNotFoundException
     *             Thrown in case of Entity is not present in system.
     * @throws CoreEntityServiceException
     *             Thrown in case of getting CA from db.
     * @return issuer private key from the database.
     */
    public KeyIdentifier getKeyIdentifier(final String cAName) throws CoreEntityNotFoundException, CoreEntityServiceException {

        logger.info("Getting private key of {} from the database ", cAName);

        final CertificateAuthorityData certificateAuthorityData = getCA(cAName);
        final Set<KeyIdentifierData> cAKeys = certificateAuthorityData.getcAKeys();
        final KeyIdentifierData activeKeysOfCA = getActiveKeys(cAKeys);

        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId(activeKeysOfCA.getKeyIdentifier());
        return keyIdentifier;
    }

    /**
     * Gets the {@link AlgorithmData} from the database based on the algorithm type provided.
     * 
     * @param algorithm
     *            {@link Algorithm} which provides name and keysize of algorithm.
     * @return {@link AlgorithmData} returned from the database.
     */
    public AlgorithmData getAlgorithmData(final Algorithm algorithm) {

        final HashMap<String, Object> parameters = new HashMap<>();

        if (algorithm.getType() == AlgorithmType.ASYMMETRIC_KEY_ALGORITHM) {
            parameters.put(NAME, algorithm.getName());
            parameters.put(ALGORITHM_KEY_SIZE, algorithm.getKeySize());
        } else if (algorithm.getType() == AlgorithmType.SIGNATURE_ALGORITHM) {
            parameters.put(NAME, algorithm.getName());
        }
        parameters.put(ALGORITHM_TYPE, algorithm.getType());
        final List<AlgorithmData> algorithmDatas = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);
        if (!algorithmDatas.isEmpty()) {
            return algorithmDatas.get(0);
        }
        return null;
    }

    /**
     * Saves Keys information in the database and returns the saved Keys.
     * 
     * @param keyData
     *            keyData to be saved in the database.
     * @return keyData saved in the database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case if entity already exists in database.
     */
    public KeyIdentifierData storeAndReturnKeyData(final KeyIdentifierData keyData) throws CoreEntityAlreadyExistsException {

        try {
            // check for active keys existence in the database. if exists make the ACTIVE to INACTIVE.
            persistenceManager.createEntity(keyData);
            return keyData;
        } catch (javax.persistence.EntityExistsException entityExistsException) {
            // TODO : These exceptions will be revisited as part of user story : TORF-55367
            logger.error(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE, entityExistsException);
            throw new CoreEntityAlreadyExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE);
        }
    }

    /**
     * Updates {@link CertificateGenerationInfoData} with generated {@link CertificateData}
     * 
     * @param certificateGenerationInfoData
     *            Entity that needs to be updated with generated certificate
     * @param certificateData
     *            generated certificate for that CertificateGenerationInfo
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     */
    public void updateCertificateGenerationInfo(final CertificateGenerationInfoData certificateGenerationInfoData, final CertificateData certificateData) throws CertificateServiceException {

        logger.info("Updating certificate generation info for CA entity : {}", certificateGenerationInfoData.getcAEntityInfo().getName());
        certificateGenerationInfoData.setCertificateData(certificateData);
        try {
            persistenceManager.updateEntity(certificateGenerationInfoData);
        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE);
            systemRecorder.recordError("PKICORE.UpdateCertificateGenerationInfo", ErrorSeverity.ERROR, "CertificatePersistenceHelper", "CertificateGenerationInfoData",
                    "Error occured while updating CA entity " + certificateGenerationInfoData.getcAEntityInfo().getName());
            throw new CertificateServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, exception);
        }
    }

    /**
     * This method will update certificate status to EXPIRED for all certificates whose validity has expired.
     *
     * @throws CertificateStateChangeException
     *             in case of Certificate status updation failed.
     */
    public void updateCertificateStatusToExpired() throws CertificateStateChangeException {
        logger.debug("Updating the certificate status in pki-core");
        int updatedEntityCount = 0;
        final HashMap<String, Object> parameters = new HashMap<>();
        final List<Integer> certStatus = new ArrayList<>();
        certStatus.add(CertificateStatus.ACTIVE.getId());
        certStatus.add(CertificateStatus.INACTIVE.getId());
        certStatus.add(CertificateStatus.REVOKED.getId());
        parameters.put("status", certStatus);
        final Query query = persistenceManager.getEntityManager().createQuery(updateCertStatusToExpiredQuery);
        query.setParameter("status", CertificateStatus.EXPIRED.getId());
        query.setParameter("currDate", new Date());
        query.setParameter("certStatus", certStatus);

        try {
            updatedEntityCount = query.executeUpdate();
        } catch (PersistenceException | IllegalStateException e) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Certificate status");
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper",
                    "CertificateGenerationInfo", "Error occured while updating the certificate status to EXPIRED");
            throw new CertificateStateChangeException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Certificate status", e);
        }
        logger.debug("Updated certificate status for {} entities in pki-core", updatedEntityCount);
        systemRecorder.recordSecurityEvent("PKICore.CertificateManagement", "CertificatePersistenceHelper", "Updated certificate status for"
                + updatedEntityCount + "entities in pki-core", "PKICORE.UPDATE_CERTIFICATE_STATUS_EXPIRED", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    private EntityInfoData makeEntityCertificateInActive(final EntityInfoData entityData) {
        final List<CertificateData> certificateDatas = getCertificateDatas(entityData.getName(), CertificateStatus.ACTIVE);
        for (final CertificateData certificateData : certificateDatas) {
            if (certificateData.getStatus() == CertificateStatus.ACTIVE) {
                persistenceManager.updateCertificateStatus(certificateData.getId(), CertificateStatus.INACTIVE.getId());
                persistenceManager.refresh(entityData);
                break;
            }
        }
        return entityData;
    }

    private CertificateAuthorityData makeCACertificateInActive(final CertificateAuthorityData certificateAuthorityData) throws CertificateServiceException, CoreEntityNotFoundException {

        logger.debug("Update CA Certificate status to INACTIVE using : {}", certificateAuthorityData.getName());
        final Set<CertificateData> certificates = certificateAuthorityData.getCertificateDatas();

        for (final CertificateData certData : certificates) {
            if (CertificateStatus.ACTIVE == certData.getStatus()) {
                certData.setStatus(CertificateStatus.INACTIVE);

                try {
                    final CertificateAuthorityData certAuthorityData = persistenceManager.updateEntity(certificateAuthorityData);
                    persistenceManager.refresh(certAuthorityData);
                } catch (EntityNotFoundException entityNotFoundException) {
                    logger.error("Error while updating the Entity Status to INACTIVE : {} ", entityNotFoundException.getMessage());
                    systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper",
                            "CertificateAuthorityData", "Entity not found with SubjectDN: " + certData.getSubjectDN());
                    throw new CoreEntityNotFoundException("Error while updating the Entity Status : ", entityNotFoundException);
                } catch (TransactionRequiredException transactionRequiredException) {
                    logger.error("Error while updating the Entity Status to INACTIVE : {}", transactionRequiredException.getMessage());
                    systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificatePersistenceHelper",
                            "CertificateAuthorityData", "Transaction required exception while updating entity with SubjectDN: " + certData.getSubjectDN());
                    throw new CertificateServiceException("Error while updating the Entity Status : ", transactionRequiredException);
                }
                break;
            }
        }
        return certificateAuthorityData;
    }

    /**
     * Gets Active KeyKeyIdentifierData for CA
     * 
     * @param cAKeys
     *            Set of KeyIdentifierDatas
     * 
     * @return Active KeyKeyIdentifierData for CA
     */
    public KeyIdentifierData getActiveKeys(final Set<KeyIdentifierData> cAKeys) {

        KeyIdentifierData activeKeysData = null;
        if (!cAKeys.isEmpty()) {
            for (final KeyIdentifierData keyData : cAKeys) {
                if (keyData.getStatus() == KeyPairStatus.ACTIVE) {
                    activeKeysData = keyData;
                }
            }
        }
        return activeKeysData;
    }

    /**
     * Gets Active KeyKeyIdentifierData for CA.
     *
     * @param cAName
     *            CA Name.
     *
     * @return Active KeyKeyIdentifierData for CA.
     * @throws CoreEntityNotFoundException
     *             in case of Entity is not present in the system.
     */
    public KeyIdentifierData getActiveKeyIdentifier(final String cAName) throws CoreEntityNotFoundException {

        logger.debug("Fetch Active Key identifier for CA : {} ", cAName);
        final CertificateAuthorityData certificateAuthorityData = getCA(cAName);
        final Set<KeyIdentifierData> cAKeys = certificateAuthorityData.getcAKeys();
        return getActiveKeys(cAKeys);
    }

    /**
     * This method will get the CertificateData JPA object from database when a Certificate object is passed
     *
     * @param certificate
     *            is the Certificate Class contain the certificate details
     * 
     * @return CertificateData is the CertificateData Class contain the certificate details
     * @throws CertException
     * 
     */
    public CertificateData getCertificateData(final com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate certificate) throws CertException {
        CertificateData certificateData = null;
        try {
            certificateData = persistenceManager.findEntity(CertificateData.class, certificate.getId());
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while fetching certificate" + persistenceException.getMessage());
            throw new CertException(ErrorMessages.CERTIFICATE_EXCEPTION, persistenceException);
        }
        return certificateData;
    }

    /**
     * Updates ACTIVE keys of CA Entity to INACTIVE state if exists.
     * 
     * @param keyIdentifierData
     *            keyIdentifierData to be updated in the database.
     * @param keyPairStatus
     *            key pair status of KeyIdentifier
     * @throws PersistenceException
     */
    public void updateKeyIdentifierStatus(final KeyIdentifierData keyIdentifierData, final KeyPairStatus keyPairStatus) throws PersistenceException {

        keyIdentifierData.setStatus(keyPairStatus);
        persistenceManager.updateEntity(keyIdentifierData);

    }

    private List<CertificateData> getCertificateDatas(final String entityName, final CertificateStatus... certificateStatuses) throws PersistenceException {

        final List<Integer> certificateStatusIds = new ArrayList<>();
        for (final CertificateStatus certificateStatus : certificateStatuses) {
            certificateStatusIds.add(certificateStatus.getId());
        }

        final Query query = persistenceManager.getEntityManager().createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS);

        query.setParameter("name", entityName);
        query.setParameter("statusList", certificateStatusIds);

        final List<CertificateData> certificateDatas = query.getResultList();

        return certificateDatas;
    }
}
