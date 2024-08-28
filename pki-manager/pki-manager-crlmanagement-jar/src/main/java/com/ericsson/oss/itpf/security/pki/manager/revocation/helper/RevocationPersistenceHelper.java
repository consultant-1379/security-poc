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
package com.ericsson.oss.itpf.security.pki.manager.revocation.helper;

import java.math.BigInteger;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class will help to get certificate.It provides following operations getCertificate with different parameters.
 * <ul>
 * <li>Get all the Certificates of given CA/End Entity with given entity name and type</li>
 * <li>Get particular Certificate with certificate identifier</li>
 * </ul>
 *
 * @author xvambur
 *
 */
public class RevocationPersistenceHelper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @PersistenceContext(unitName = "PKIManager")
    private EntityManager entityManager;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    EntityCertificatePersistenceHelper entityPersistenceHelper;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method will fetch certificate for the given serial number and issuer name
     *
     * @param certificateIdentifier
     *            is the object of CertificateIdentifier, has the fields issuerName and serialNumber.
     *
     * @return Certificate - Returns the Certificate for the given entity
     *
     * @throws IssuerNotFoundException
     *             thrown when issuer is not found.
     * @throws CertificateNotFoundException
     *             certificate = certificateHelper.getCertificate(certificateIdentifier); thrown when no valid Certificate found for Entity.
     */
    public Certificate getCertificate(final CertificateIdentifier certificateIdentifier) throws IssuerNotFoundException, RevocationServiceException, CertificateNotFoundException
             {
        logger.debug("Enter into getCertificate method to fetch certificate");
        Certificate certificate = null;
        try {
            certificate = certificatePersistenceHelper.getCertificate(certificateIdentifier);
        } catch (final CertificateServiceException certificateServiceException) {
            logger.debug("Error while fetching certificate to perform revocation ", certificateServiceException);
            logger.error("Error when fetching certificate" + certificateServiceException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.CERTIFICATE_SERVICE_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error while fetching certificate with serial number" + certificateIdentifier.getSerialNumber());
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
        return certificate;
    }

    /**
     * This method will fetch certificate for the given serial number
     *
     * @param DNBasedCertificateIdentifier
     *            is the object of DNBasedCertificateIdentifier, has the fields Subject Dn,Issuer Dn and serialNumber.
     *
     * @return List<Certificate> - Returns the Certificates for the given entity
     *
     * @throws CertificateNotFoundException
     *             certificate = certificateHelper.getCertificate(certificateIdentifier); thrown when no valid Certificate found for Entity.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public List<Certificate> getCertificateList(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier) throws CertificateNotFoundException, RevocationServiceException {
        logger.debug("Enter into getCertificate method to fetch certificates");
        List<Certificate> certificateList;
        try {
            certificateList = certificatePersistenceHelper.getCertificateBySerialNumber(dnBasedCertificateIdentifier.getCerficateSerialNumber());
        } catch (final CertificateServiceException certificateServiceException) {
            logger.debug("Error while fetching certificate lists ", certificateServiceException);
            logger.error("Error when fetching certificate" + certificateServiceException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.CERTIFICATE_SERVICE_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation Manager",
                    "Error while fetching certificate with serial number" + dnBasedCertificateIdentifier.getCerficateSerialNumber());
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
        return certificateList;

    }

    /**
     * This method will get entity data JPA Object
     *
     * @param entityName
     *            - is the name of the Entity
     * @return - EntityData JPA object
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public EntityData getEntityData(final String entityName) throws EntityNotFoundException, RevocationServiceException {
        EntityData entityData = new EntityData();
        logger.info("Fetching Entity data for the given entity name {}" , entityName);
        try {
            entityData = entityPersistenceHelper.getEntityData(entityName);
        } catch (EntityServiceException exception) {
            logger.error("Error while fetching  Entity" + exception.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.CERTIFICATE_SERVICE_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error while fetching entity with name " + entityName);
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }catch (PersistenceException e) {
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Certificate Revocation",
                    "Error occured while processing the request for Entity :" + entityName);
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, e);
        }
        return entityData;

    }

    /**
     * This method will get CAEntityData data JPA Object
     *
     * @param entityName
     *            - is the name of the CAEntity
     * @return - CAEntityData JPA object
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public CAEntityData getCAEntityData(final String entityName) throws EntityNotFoundException, RevocationServiceException {
        CAEntityData caEntityData = new CAEntityData();
        logger.info("Fetching CAEntity data for the given entity name");
        try {
            caEntityData = caPersistenceHelper.getCAEntity(entityName);
        } catch (PersistenceException e) {
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured while getting the CA Entity :" + entityName);
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, e);
        } catch (CANotFoundException e) {
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.CA_NOT_FOUND", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate", "CA Entity not found with name :"
                    + entityName);
            throw new EntityNotFoundException(e.getMessage(), e);
        } catch (EntityServiceException exception) {
            logger.error("Error when fetching  CA Entity" + exception.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.CERTIFICATE_SERVICE_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error while fetching ca entity with name " + entityName);
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }
        return caEntityData;
    }

    /**
     * This method will get CertificateData data JPA Object
     *
     * @param certificate
     *            - is the certificate object model
     * @return - CertificateData JPA object
     * @throws RevocationServiceException
     */
    public CertificateData getCertificateData(final Certificate certificate) throws RevocationServiceException {
        logger.info("Getting Certificate data for the given certificate");
        try {
            return certificatePersistenceHelper.getCertificateData(certificate);
        } catch (CertificateServiceException e) {
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured while getting certificate with serial number:" + certificate.getSerialNumber());
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, e);
        }
    }

    /**
     * This method will store the revocation request data
     *
     * @param RevocationRequestData
     *            is the RevocationRequestData that needs to be filled and persisted
     * @param revocationCertificateData
     *            is the CertificateData Class contain the certificate details
     * @param reason
     *            is the RevocationReason Enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the date on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     *
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void storeRevocationRequestData(final RevocationRequestData revocationRequestData, final List<CertificateData> revocationCertificateData, final RevocationReason revocationReason,
            final Date invalidityDate) throws RevocationServiceException {
        logger.debug("Store revocation request details");
        try {
            for (CertificateData certificate : revocationCertificateData) {
                revocationRequestData.getCertificatesToRevoke().add(certificate);
            }

            final CrlEntryExtensions crlEntryExtensions = new CrlEntryExtensions();

            final InvalidityDate invalidityDateObject = new InvalidityDate();
            invalidityDateObject.setInvalidityDate(invalidityDate);
            crlEntryExtensions.setInvalidityDate(invalidityDateObject);

            final ReasonCode reasonCodeObject = new ReasonCode();
            reasonCodeObject.setRevocationReason(revocationReason);
            crlEntryExtensions.setReasonCode(reasonCodeObject);

            revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(crlEntryExtensions));

            revocationRequestData.setStatus(RevocationRequestStatus.NEW);
            persistenceManager.createEntity(revocationRequestData);
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while storing an revocation request" + persistenceException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured while persisting the revocation request data");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }

    }

    /**
     * This method will update the revoked status of certificate
     *
     * @param RevocationRequestData
     *            is the RevocationRequestData object for which the certificates need to be updated to revoked status.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void updateCertificateStatusForRevocationRequest(final RevocationRequestData revocationRequestData) throws RevocationServiceException {
        logger.debug("Updating certificateStatus for revocation request ");
        try {
            final Set<CertificateData> certData = new HashSet<CertificateData>();
            for (CertificateData certificateData : revocationRequestData.getCertificatesToRevoke()) {
                certificateData.setRevokedTime(new Date());
                certificateData.setStatus(CertificateStatus.REVOKED.getId());
                certData.add(certificateData);
            }
            revocationRequestData.setCertificatesToRevoke(certData);
            persistenceManager.updateEntity(revocationRequestData);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while updating certificate status for revocation request ", persistenceException);
            logger.error("Error occured while updating certificate status" + persistenceException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.DATABASE_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation Manager",
                    "Error occured while updating revoked status of certificate");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
        logger.debug("CertificateStatus for revocation request updated");
    }

    /**
     * This method will update the revoked status of revocationRequestData
     *
     * @param revocationRequestData
     *            - is the RevocationRequestData Class contain the revocation request details
     * @param status
     *            is the RevocationStatus that needs to be set for the revocation request
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void updateRevocationRequestStatus(final RevocationRequestData revocationRequestData, final RevocationRequestStatus status) throws RevocationServiceException {
        logger.info("Updating the revoked status of RevocationRequestData");
        try {
            revocationRequestData.setStatus(status);
            persistenceManager.updateEntity(revocationRequestData);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while updating certificate status while updating revocation request status ", persistenceException);
            logger.error("Error occured while updating certificate status" + persistenceException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.UPDATE_REVOKE_REQUEST_STATUS", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation Manager",
                    "Error occured while revoking the certificates");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }

    }

    /**
     * This method will get CAentity data JPA Object
     *
     * @param certificate
     *            id - is the id of the certificate object model
     * @return CAEntityData - is the CAentity JPA object
     *
     * @throws RevocationServiceException
     *             thrown when internal db error occurs while getting CAEntityData for revocation.
     *
     */
    public CAEntityData getCaEntityById(final long certificateId) throws RevocationServiceException {
        logger.info("Getting CA Entity data by the given CertificateID {} ", certificateId);
        CAEntityData caentity = null;
        try {
            try {
                caentity = persistenceManager.findEntity(CAEntityData.class, getCaEntityIdFromCertificateId(certificateId));
            } catch (final EntityNotFoundException entityNotFoundException) {
                logger.debug("Error occured while finding CAentity by ID ", entityNotFoundException);
                return null;
            }
            return caentity;
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while finding CA Entity for revoking its certificates ", persistenceException);
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured while finding CA Entity for revoking its certificates");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
    }

    /**
     * This method will get entity data JPA Object
     *
     * @param certificate
     *            - is the certificate object model
     * @return EntityData - is the entity JPA object
     *
     * @throws EntityNotFoundException
     *             thrown when entity is not found in database.
     * @throws RevocationServiceException
     *             thrown when internal db error occurs while retrieving Entity.
     */
    public EntityData getEntityById(final Certificate certificate) throws EntityNotFoundException, RevocationServiceException {
        logger.info("Getting Entity data by the given CertificateID {} ", certificate.getId());
        EntityData entity = null;
        try {
            logger.info("Fetch entity id with getEntityId method" + certificate.getId());
            try {
                entity = persistenceManager.findEntity(EntityData.class, getEntityIdFromCertificateId(certificate.getId()));
            } catch (final javax.persistence.EntityNotFoundException entityNotFoundException) {
               logger.debug("Entity not found for revoking its certificates ", entityNotFoundException);
                systemRecorder.recordError("PKI_MANAGER_REVOCATION.ENTITY_NOT_FOUND", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificates",
                        "Entity not found for revoking its certificates.");
                throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND);
            }
            return entity;
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while finding Entity for revoking its certificates ", persistenceException);
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.DATABASE_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificates",
                    "Error occured while finding Entity for revoking its certificates.");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
    }

    /**
     * This method will get entityId for CAEntity with given certificateid
     *
     * @param certificate_id
     *            is the Certificate id of the certificate
     * @return long - CAEntityId
     */
    public long getCaEntityIdFromCertificateId(final long certificate_id) throws EntityNotFoundException {
        logger.info("Fetch CAentity id with getEntityId method");
        logger.info("certificate id {}", certificate_id);
        final String queryString = "select ca_id from ca_certificate where certificate_id = " + String.valueOf(certificate_id);
        final Query query = entityManager.createNativeQuery(queryString);
        final List entityId = query.getResultList();
        BigInteger entity = null;
        if (entityId.size() > 0) {
            entity = (BigInteger) entityId.get(0);
        } else {
            throw new EntityNotFoundException();
        }
        return entity.longValue();
    }

    /**
     * This method will get entityId for Entity with given certificateid
     *
     * @param certificate_id
     *            is the Certificate id of the certificate
     * @return long - EntityId
     */
    public long getEntityIdFromCertificateId(final long certificate_id) throws EntityNotFoundException {
        logger.info("Fetch entity id with getEntityId method");
        logger.info("certificate id {}", certificate_id);
        final String queryString = "select entity_id from entity_certificate where certificate_id = " + String.valueOf(certificate_id);
        final Query query = entityManager.createNativeQuery(queryString);
        final List entityId = query.getResultList();
        BigInteger entity = null;
        if (entityId.size() > 0) {
            entity = (BigInteger) entityId.get(0);
        } else {
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.ENTITY_NOT_FOUND", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificates", "Entity not found for certificate with ID :"
                    + certificate_id);
            throw new EntityNotFoundException();
        }
        return entity.longValue();
    }
}
