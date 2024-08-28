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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl;

import java.io.IOException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.RevocationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.RevocationRequestModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.eserviceref.CRLManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.TDPSUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.CoreEntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.revocation.validator.RevocationValidator;

/**
 * This class will provide Revocation Service. It provides below Revocation operations.
 * <ul>
 * <li>Revoke all the Certificates of given CAEntity or Entity</li>
 * <li>Revoke a particular Certificate</li>
 * </ul>
 *
 * @author xvambur
 *
 */
public class RevocationManager {

    @Inject
    Logger logger;

    @Inject
    RevocationPersistenceHelper revocationPersistenceHelper;

    @Inject
    CRLManagerEServiceProxy crlManagerEServiceProxy;

    @Inject
    RevocationValidator revocationValidator;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Inject
    RevocationRequestModelMapper revocationRequestModelMapper;

    @Inject
    CRLUnpublishNotifier crlUnpublishNotifier;

    @Inject
    TDPSUnpublishNotifier tdpsUnpublishNotifier;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    EntitiesModelMapperFactory modelMapperFactory;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CoreEntitiesManager coreEntitiesManager;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    RevocationManagementAuthorizationManager revocationManagementAuthorizationManager;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntityMapper entityMapper;

    /**
     * This API method is used to revoke all the valid Certificates of the given Entity.
     *
     * @param entityName
     *            is the name of the Entity.
     * @param reason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the date on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    public void revokeEntityCertificates(final String entityName, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException, 
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, IssuerCertificateRevokedException, InvalidInvalidityDateException, 
            RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {

        logger.debug("Enter into method revokeEntityCertificates");
        revocationManagementAuthorizationManager.authorizeRevokeEntityCertificate();
        final EntityData entityData = revocationPersistenceHelper.getEntityData(entityName);

        final List<Certificate> revocationCertificateList = getEntityCertificates(entityName);

        if (revocationCertificateList.isEmpty()) {
            logger.error("Certificate not found with the given entityName: {}", entityName);
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.ACTIVE_CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "RevocationManager", "Entity Certificate Revocation", 
                    "No ACTIVE certificate found to revoke in PKI System for the Entity :" + entityName);
            throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
        }

        final List<CertificateData> revocationCertificateDataList = getRevocationCertificateDataList(revocationCertificateList);

        revocationValidator.validateCertificateChain(revocationCertificateDataList);
        revocationValidator.validateInvalidityDate(revocationCertificateDataList, invalidityDate);

        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        revocationRequestData.setEntity(entityData);
        revocationPersistenceHelper.storeRevocationRequestData(revocationRequestData, revocationCertificateDataList, revocationReason, invalidityDate);

        revokeCertificates(revocationRequestData);

        revocationPersistenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.REVOKED);
        updateEntityStatus(entityData);
        systemRecorder.recordSecurityEvent("PKIMANAGER_REVOCATION_MANAGEMENT", "RevocationManager", "Entity" + entityName + " Certificates Revoked Successfully ", 
                "REVOCATION_MANAGEMENT.REVOKE_ENTITY_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    /**
     * This method will get revocation certificate data details list
     *
     * @param revocationCertificateList
     *            - is the certificate object model list
     * @return - is the CertificateData JPA object
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     */
    private List<CertificateData> getRevocationCertificateDataList(final List<Certificate> revocationCertificateList) throws ExpiredCertificateException, RevokedCertificateException {
        logger.info("Getting the revocated certificate data details");
        List<CertificateData> revocationCertificateDataList = null;
        for (final Certificate certificate : revocationCertificateList) {
            if (certificate.getStatus().equals(CertificateStatus.EXPIRED)) {
                logger.error("Entity certificate is invalid for revocation");
                systemRecorder.recordError("PKI_MANAGER_REVOCATION.CERTIFICATE_EXPIRED", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate", 
                        "Entity certificate is expired with the serial number :" + certificate.getSerialNumber());
                throw new ExpiredCertificateException(ErrorMessages.INVALID_CERTIFICATE);
            } else if (certificate.getStatus().equals(CertificateStatus.REVOKED)) {
                logger.error("Entity certificate is invalid for revocation");
                systemRecorder.recordError("PKI_MANAGER_REVOCATION.INVALID_CERTIFICATE", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate",
                        "Entity certificate is already revoked with the serial number :" + certificate.getSerialNumber());
                throw new RevokedCertificateException(ErrorMessages.INVALID_CERTIFICATE);
            } else {
                if (revocationCertificateDataList == null) {
                    revocationCertificateDataList = new ArrayList<CertificateData>();
                }
                revocationCertificateDataList.add(revocationPersistenceHelper.getCertificateData(certificate));
            }
        }
        return revocationCertificateDataList;
    }

    /**
     * This method is used to revoke all the valid Certificates of the given CAEntity.
     *
     * @param caEntityName
     *            is the name of the CAEntity.
     * @param reason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the date on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     *
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */

    public void revokeCAEntityCertificates(final String caEntityName, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException, 
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, 
            RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {
        logger.debug("Enter into method revokeEntityCertificate");

        revocationManagementAuthorizationManager.authorizeRevokeCACertificate();
        final CAEntityData caEntityData = revocationPersistenceHelper.getCAEntityData(caEntityName);

        if (caEntityData.getCertificateAuthorityData().isRootCA()) {
            if (caEntityData.getCertificateAuthorityData().isIssuerExternalCA()) {
                logger.error("Root CA{}", caEntityData.getCertificateAuthorityData().getName(), "cannot be revoked. Root CA is sub CA of External CA");
                systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager", "Root CA " + caEntityName + " cannot be revoked and is the SubCA of external CA", 
                        "RootCARevocation", ErrorSeverity.ERROR, "FAILURE");
                throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED);

            }
            logger.debug("Cannot revoke RootCA Certificate");
            systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager", "Root CA " + caEntityName + " can not be revoked", "RootCARevocation", ErrorSeverity.ERROR, 
                    "FAILURE");
            throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED);
        }

        final List<Certificate> revocationCertificateList = getCAEntityCertificates(caEntityName);

        if (revocationCertificateList.isEmpty()) {
            logger.error("Certificate not found with the given entityName: {}", caEntityName);
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.ACTIVE_INACTIVE_CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate", 
                    "No Active or Inactive certificate found with the given CA Entity Name :" + caEntityName);
            throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
        }

        final List<CertificateData> revocationCertificateDataList = getRevocationCertificateDataList(revocationCertificateList);

        revocationValidator.validateCertificateChain(revocationCertificateDataList);
        revocationValidator.validateInvalidityDate(revocationCertificateDataList, invalidityDate);

        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        revocationRequestData.setCaEntity(caEntityData);
        revocationPersistenceHelper.storeRevocationRequestData(revocationRequestData, revocationCertificateDataList, revocationReason,
                invalidityDate);

        revokeCertificates(revocationRequestData);

        revocationPersistenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.REVOKED);
        updateEntityStatus(caEntityData);
        systemRecorder.recordSecurityEvent("PKIMANAGER_REVOCATION_MANAGEMENT", "RevocationManager", "CAEntity " + caEntityName + " Certificates Revoked Successfully ", 
                "REVOCATION_MANAGEMENT.REVOKE_CA_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    /**
     * This method is used to revoke particular Certificate of an CAEntity or Entity. The details of the Certificate is given in the
     * CertificateIdentifier.
     *
     * @param certificateIdentifier
     *            is the object of CertificateIdentifier, has the fields issuerName and serialNumber.
     * @param reason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the optional value and it is the on which it is known or suspected that the private key was compromised or that the Certificate
     *            otherwise became invalid.
     *
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the CAEntity or Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws IssuerNotFoundException
     *             thrown when issuer is not found.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    public void revokeCertificateByIssuerName(final CertificateIdentifier certificateIdentifier, final RevocationReason revocationReason, final Date invalidityDate) 
                    throws CertificateNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, 
            IssuerCertificateRevokedException, IssuerNotFoundException, RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {
        logger.info("Enter into revoke Certificate by Certificate identifier");
        Certificate certificate = null;
        certificate = revocationPersistenceHelper.getCertificate(certificateIdentifier);
        revokeCertificate(certificate, revocationReason, invalidityDate);
        systemRecorder.recordSecurityEvent("PKIMANAGER_REVOCATION_MANAGEMENT", "RevocationManager", "CAEntity/Entity Certificate Revoked Successfully: {}" + certificateIdentifier, 
                "REVOCATION_MANAGEMENT.REVOKE_BY_ISSUER_NAME", ErrorSeverity.INFORMATIONAL, "SUCCESS");

    }

    /**
     * This method is used to revoke particular Certificate of an CAEntity or Entity. The details of the Certificate is given in the
     * CertificateIdentifier.
     *
     * @param dnBasedCertificateIdentifier
     *            is the object of CertificateIdentifier, has the fields issuerName and serialNumber.
     * @param revocationReason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the optional value and it is the on which it is known or suspected that the private key was compromised or that the Certificate
     *            otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the CAEntity or Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void revokeCertificateByDN(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier, final RevocationReason revocationReason, final Date invalidityDate) 
            throws CertificateNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, 
            IssuerCertificateRevokedException, RevokedCertificateException, RootCertificateRevocationException, RevocationServiceException {
        boolean revoked = false;
        logger.info("Enter into revoke Certificate by DNBasedCertificateIdentifier");
        List<Certificate> certificateList = revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier);
        for (final Certificate certificate : certificateList) {
            final String subjectDN = dnBasedCertificateIdentifier.getSubjectDN();
            final String certificateSubjectDn = certificate.getSubject().toASN1String();
            final String issuerDN = dnBasedCertificateIdentifier.getIssuerDN();
            if (certificate.getIssuerCertificate() == null) {
                logger.error("Root CA cannot be revoked");
                systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager", 
                        "Root CA can not be revoked with certificate with serial number :" + certificate.getSerialNumber(), "RootCARevocation", ErrorSeverity.ERROR, "FAILURE");
                throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED);
            }
            final String certificateIssuerDn = certificate.getIssuerCertificate().getSubject().toASN1String();
            final boolean compareSubjectDn = SubjectUtils.matchesDN(subjectDN, certificateSubjectDn);
            final boolean compareIssuerDn = SubjectUtils.matchesDN(issuerDN, certificateIssuerDn);

            if ((compareSubjectDn) && (compareIssuerDn)) {
                revokeCertificate(certificate, revocationReason, invalidityDate);

                revoked = true;
            }
        }
        if (!revoked) {
            logger.error("Subject DN or IssuerDn not matched for the certificate with serial number "
                    + dnBasedCertificateIdentifier.getCerficateSerialNumber());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.SUBJECTDN_ISSUERDN_NOT_FOUND", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate", 
                    "The Subject and IssuerDN are not found for the certificate with serial number:"
                            + dnBasedCertificateIdentifier.getCerficateSerialNumber());
            throw new CertificateNotFoundException(ErrorMessages.SUBJECTDN_ISSUERDN_NOT_FOUND);
        }
        systemRecorder.recordSecurityEvent("PKIMANAGER_REVOCATION_MANAGEMENT", "RevocationManager", "CAEntity/Entity Certificate Revoked Successfully: {} " + dnBasedCertificateIdentifier, 
                "REVOCATION_MANAGEMENT.REVOKE_BY_DN",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    /**
     * This method is used to revoke particular Certificate of an CAEntity or Entity.
     *
     * @param certificate
     *            is the object of Certificate
     * @param revocationReason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the optional value and it is the on which it is known or suspected that the private key was compromised or that the Certificate
     *            otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the CAEntity or Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    private void revokeCertificate(final Certificate certificate, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException, 
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, 
            RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {
        logger.info("Enter into revoke Certificate ");
        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        final CAEntityData caentity = revocationPersistenceHelper.getCaEntityById(certificate.getId());
        if (caentity == null) {
            revocationManagementAuthorizationManager.authorizeRevokeEntityCertificate();
            final EntityData entity = revocationPersistenceHelper.getEntityById(certificate);
            revocationRequestData.setEntity(entity);
        } else {
            revocationManagementAuthorizationManager.authorizeRevokeCACertificate();
            if (caentity.getCertificateAuthorityData().isRootCA()) {
                if (caentity.getCertificateAuthorityData().isIssuerExternalCA()) {
                    logger.error("Root CA{}", caentity.getCertificateAuthorityData().getName(), "cannot be revoked. Root CA is sub CA of External CA");
                    systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager", "RootCA is the SubCA of External CA and cannot be revoked with certificate serial number :"
                            + certificate.getSerialNumber(), "RootCARevocation", ErrorSeverity.ERROR, "FAILURE");
                    throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED);

                }
                logger.error("Root CA cannot be revoked");
                systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager",
                        "Root CA can not be revoked with certificate with serial number :" + certificate.getSerialNumber(), "RootCARevocation",
                        ErrorSeverity.ERROR, "FAILURE");
                throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED);
            }
            revocationRequestData.setCaEntity(caentity);
        }
        final List<Certificate> revocationCertificateList = new ArrayList<Certificate>();
        revocationCertificateList.add(certificate);
        final List<CertificateData> revocationCertificateDataList = getRevocationCertificateDataList(revocationCertificateList);

        revocationValidator.validateCertificateChain(revocationCertificateDataList);
        revocationValidator.validateInvalidityDate(revocationCertificateDataList, invalidityDate);

        revocationPersistenceHelper.storeRevocationRequestData(revocationRequestData, revocationCertificateDataList, revocationReason, invalidityDate);

        revokeCertificates(revocationRequestData);

        revocationPersistenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.REVOKED);
        if (caentity != null) {
            updateEntityStatus(caentity);
        } else {
            updateEntityStatus(revocationPersistenceHelper.getEntityById(certificate));
        }

    }

    private List<Certificate> getEntityCertificates(final String entityName) throws CertificateNotFoundException, InvalidEntityAttributeException, RevocationServiceException {
        logger.debug("Enter into getCertificate method to fetch certificates for {}", entityName);

        try {
            final List<Certificate> certificateList = entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
            if (certificateList == null) {
                throw new CertificateNotFoundException(ErrorMessages.NO_VALID_CERTIFICATE);
            }
            return certificateList;
        } catch (final PersistenceException exception) {
            logger.error("Exception while retrieving certificate", exception.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate",
                    "Error occured while getting Certificates for entity :" + entityName);
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (final CertificateException | IOException certificateException) {
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate",
                    "Error occured while getting Certificates for entity :" + entityName);
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR + certificateException);
        }
    }

    /**
     * This method will fetch certificate for the given CAentity
     *
     * @param caEntityName
     *            is the name of the CAEntity
     *
     * @return List<Certificate> Returns the Certificate for the given CAentity
     *
     * @throws CertificateNotFoundException
     *             thrown when no valid Certificate found for Entity.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    private List<Certificate> getCAEntityCertificates(final String caEntityName) throws CertificateNotFoundException, InvalidEntityAttributeException, RevocationServiceException {
        logger.debug("Enter into getCACertificate method to fetch certificate for {}", caEntityName);
        try {
            final List<Certificate> certificates = caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
            if (certificates == null) {
                throw new CertificateNotFoundException(ErrorMessages.NO_VALID_CERTIFICATE);
            }
            return certificates;
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate",
                    "Error occured while getting active and inactive Certificates of  CA entity:" + caEntityName);
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        } catch (final CertificateException | IOException certificateException) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, certificateException.getMessage());
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationManager", "Revocation of Certificate",
                    "Error occured while getting active and inactive Certificates of  CA entity:" + caEntityName);
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR + certificateException);
        }
    }

    /**
     * This method will revoke the core certificates
     *
     * @param revocationRequestData
     *            - is the RevocationRequestData Class contain the revocation request details
     * @throws CertificateNotFoundException
     *             thrown when the issuer certificate is not found.
     * @throws EntityNotFoundException
     *             thrown when the issuer entity is not found
     * @throws ExpiredCertificateException
     *             thrown when the certificate status is expired
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevokedCertificateException
     *             thrown when the certificate status is revoked
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             thrown when the given revocation request is for Root CA.
     */
    private void revokeCertificates(final RevocationRequestData revocationRequestData) throws CertificateNotFoundException, EntityNotFoundException, ExpiredCertificateException, 
            InvalidEntityAttributeException, IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {
        logger.info("Revoking the Core Certificates with Revocation Request Data");
        RevocationRequest revocationRequest;
        try {

            logger.info("revokeCertificates method is invoked");
            revocationRequest = revocationRequestModelMapper.toAPIModel(revocationRequestData);
            crlManagerEServiceProxy.getRevocationService().revokeCertificate(revocationRequest);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException e) {
            logger.error("Revocation Failed: Entity is not found ");
            throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND, e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException e) {
            logger.error("Revocation Failed: Certificate is not found ");
            throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND, e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException e) {
            logger.error("Revocation Failed: Certificate has expired");
            throw new ExpiredCertificateException(ErrorMessages.INVALID_CERTIFICATE, e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException e) {
            logger.error("Revocation Failed: Certificate is already revoked");
            throw new RevokedCertificateException(ErrorMessages.INVALID_CERTIFICATE, e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificatePathValidationException e) {
            logger.error("Revocation Failed: Issuer Certificate is revoked");
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.REVOKE_CERTIFICATES", ErrorSeverity.ERROR, "RevocationManager", "End Entity", "Issuer Certificate is revoked in pki-manager");
            throw new IssuerCertificateRevokedException(ErrorMessages.ISSUER_CERTIFICATE_ALREADY_REVOKED, e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.revocation.RootCARevocationException e) {
            logger.error("Revocation Failed: " + e.getMessage());
            throw new RootCertificateRevocationException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException e) {
            logger.error("Revocation Failed: Internal error occured");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, e);
        } catch (final CertificateException | IOException e) {
            logger.error("Revocation Failed: Internal error occured");
            throw new InvalidEntityAttributeException(ErrorMessages.INTERNAL_ERROR, e);
        }
        revocationPersistenceHelper.updateCertificateStatusForRevocationRequest(revocationRequestData);
        unpublishRevokedCertificates(revocationRequest);
    }

    private void unpublishRevokedCertificates(final RevocationRequest revocationRequest) throws RevocationServiceException {
        logger.info("Unpublishing the revoked certificates with revocation request");
        try {
            final List<Certificate> certificates = revocationRequest.getCertificatesToBeRevoked();
            final EntityType entityType = getEntityType(revocationRequest);

            switch (entityType) {
            case CA_ENTITY:
                final String caName = revocationRequest.getCaEntity().getName();

                final List<CACertificateIdentifier> caCertificateIdentifiers = generateCACertificateIdentifiers(caName, certificates);
                crlUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

                tdpsUnpublishNotifier.notify(EntityType.CA_ENTITY, caName, certificates);
                break;

            case ENTITY:
                final String entityName = revocationRequest.getEntity().getName();
                tdpsUnpublishNotifier.notify(EntityType.ENTITY, entityName, certificates);
                break;

            default:
                logger.error("Unknown enitity type");
            }
        } catch (final CertificateEncodingException certificateEncodingException) {
            logger.error("TDPS Revocation Failed: Exception occured while encoding the certificate");
            systemRecorder.recordError("PKI_MANAGER_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationManager", "Unpublish Certificate",
                    "Error occured while unpublishing the revoked certificate");
            throw new RevocationServiceException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
        }
    }

    private EntityType getEntityType(final RevocationRequest revocationRequest) {
        if (revocationRequest.getCaEntity() != null) {
            return EntityType.CA_ENTITY;
        } else {
            return EntityType.ENTITY;
        }
    }

    private List<CACertificateIdentifier> generateCACertificateIdentifiers(final String caName, final List<Certificate> certificates) {
        final Set<CACertificateIdentifier> caCertificateIdentifiers = new HashSet<CACertificateIdentifier>();

        for (final Certificate certificate : certificates) {
            final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier(caName, certificate.getSerialNumber());
            caCertificateIdentifiers.add(caCertificateIdentifier);
        }
        return new ArrayList<CACertificateIdentifier>(caCertificateIdentifiers);
    }

    /**
     * This method will update CA Entity status to INACTIVE if the CAEntity does not have active certificates.
     *
     * @param caEntityData
     *            is the data of the CAEntity.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB while updating entity status.
     * @throws InvalidEntityAttributeException
     *             Thrown when error occurred while updating Entity Status after revocation.
     * @throws RevocationServiceException
     *             Thrown when internal db error occurs in system.
     */
    private void updateEntityStatus(final CAEntityData caEntityData)
            throws EntityAlreadyExistsException, EntityNotFoundException, InvalidEntityAttributeException, RevocationServiceException {
        try {
            final List<Certificate> activeCertificateList = caCertificatePersistenceHelper.getCertificates(caEntityData.getCertificateAuthorityData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, 
                    CertificateStatus.INACTIVE);
            if (activeCertificateList == null) {
                caEntityData.getCertificateAuthorityData().setStatus(CAStatus.INACTIVE.getId());
                final CAEntity caEntity = caEntityMapper.toAPIFromModel(caEntityData, false);
                final CAEntity issuer = caEntityMapper.toAPIFromModelForSummary(caEntityData.getCertificateAuthorityData().getIssuer());

                caEntity.getCertificateAuthority().setIssuer(issuer.getCertificateAuthority());
                coreEntitiesManager.updateEntity(caEntity);
                persistenceManager.updateEntity(caEntityData);
            }

        } catch (final EntityServiceException | PersistenceException exception) {
            logger.error("Exception while updating Entity Status", exception.getMessage());
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (final CertificateException | IOException exception) {
            logger.error("Exception while updating Entity Status", exception.getMessage());
            throw new InvalidEntityAttributeException(ErrorMessages.INTERNAL_ERROR + exception);
        }
    }

    /**
     * This method will update Entity status to INACTIVE if the Entity does not have active or inactive certificates.
     *
     * @param entityData
     *            is the data of the Entity.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB while updating entity status.
     * @throws InvalidEntityAttributeException
     *             Thrown when error occurred while updating Entity Status after revocation.
     * @throws RevocationServiceException
     *             Thrown when internal db error occurs in system.
     */
    private void updateEntityStatus(final EntityData entityData)
            throws EntityAlreadyExistsException, EntityNotFoundException, InvalidEntityAttributeException, RevocationServiceException {
        try {
            final List<Certificate> activeCertificateList = entityCertificatePersistenceHelper.getCertificates(entityData.getEntityInfoData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, 
                    CertificateStatus.INACTIVE);
            if (activeCertificateList == null) {
                entityData.getEntityInfoData().setStatus(EntityStatus.INACTIVE);
                final Entity entity = entityMapper.toAPIFromModelForSummary(entityData);
                final CAEntity issuer = caEntityMapper.toAPIFromModelForSummary(entityData.getEntityInfoData().getIssuer());
                entity.getEntityInfo().setIssuer(issuer.getCertificateAuthority());
                coreEntitiesManager.updateEntity(entity);
                persistenceManager.updateEntity(entityData);
            }
        } catch (final EntityServiceException | PersistenceException exception) {
            logger.error("Exception while updating Entity Status", exception.getMessage());
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (final CertificateException | IOException exception) {
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR + exception);
        }
    }
}
