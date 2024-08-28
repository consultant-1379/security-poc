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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.CARekeyHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.CARenewHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.GenerateCSRHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.InitialCACertGenerationHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier.CertificateEventNotifier;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.utils.CertificateServiceExceptionUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RootCertificateRevocationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Class used for generating and listing the certificates of CAEntities.
 * 
 * <p>
 * Generating certificates, get the CAEntity and build the {@link CertificateGenerationInfo} object and pass on to PKI-Core, which will generate the certificate.
 * 
 * Listing of certificates, return the list of certificates of CAEntity based on certificate status.
 * </p>
 */
@SuppressWarnings("PMD.TooManyFields")
public class CAEntityCertificateManager extends AbstractCertificateManager {

    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    EntityHelper entityHelper;

    @Inject
    InitialCACertGenerationHandler initialCertGenerationHandler;

    @Inject
    CARenewHandler renewHandler;

    @Inject
    CARekeyHandler rekeyHandler;

    @Inject
    CertificateEventNotifier certificateEventNotifier;

    @Inject
    TDPSPersistenceHandler tdpsPersistenceHandler;

    @Inject
    RevocationManager revocationManager;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    CertificateValidator certificateValidator;

    @Inject
    CertificateHelper certificateHelper;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    GenerateCSRHandler generateCSRHandler;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    ExtCertificateModelMapper extCertificateModelMapper;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    /**
     * Generates certificate for the {@link CAEntity}.
     * 
     * @param caEntityName
     *            The CA entity name.
     * @return The Certificate object.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public Certificate generateCertificate(final String caEntityName) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        return initialCertGenerationHandler.generateCertificate(caEntityName);

    }

    /**
     * Generates certificate for the {@link CAEntity}.
     * 
     * @param caEntityName
     *            The CA entity name.
     * @param reIssueType
     * @return The Certificate object.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate of the given entity is revoked.
     */
    public void renewCertificate(final String caEntityName, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException,
            RevokedCertificateException {
        final CAEntity caEntity = entityHelper.getCAEntity(caEntityName);

        renewHandler.renewCertificate(caEntity, reIssueType);

        // TORF-90825: Use for Roll back the certificate of internal root CA which is signed by external root CA to PKI selfsigned certificate.
        caCertificatePersistenceHelper.checkAndUpdateIsIssuerExternalCA(caEntityName);
    }

    /**
     * This method supports revoke with reissue operation of CA based on reIssueType.
     * 
     * <ul>
     * <li>If ReIssueType is CA then it will reissue given CA certificate and revoke the invalid certificate</li>
     * <li>If ReIssueType is CA_WITH_IMMEDIATE_SUB_CAS then it will reissue the given CA and its SubCA certificates and then revoke the invalid certificate of given CA.</li>
     * <li>If ReIssueType is CA_WITH_ALL_CHILD_CAS then it will reissue the given CA and its hierarchy certificates and then revoke the invalid certificate of given CA.</li>
     * </ul>
     * 
     * @param caReIssueInfo
     *            The caReIssueInfo object contains the CAName and revocation details.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateNotFoundException
     *             Thrown in case certificate does not exist for the given CA Entity.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     */
    public void renewCertificate(final CAReIssueInfo caReIssueInfo, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidProfileAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException,
            RootCertificateRevocationException {

        try {

            final CAEntity caEntity = entityHelper.getCAEntity(caReIssueInfo.getName());
            final CertificateData activeCertificate = getCAActiveCertificate(caEntity.getCertificateAuthority().getName());

            checkCACanBeRevoked(caEntity);

            renewHandler.renewCertificate(caEntity, reIssueType);

            // TORF-90825: Use for Roll back the certificate of internal root CA which is signed by external root CA to PKI selfsigned certificate.
            caCertificatePersistenceHelper.checkAndUpdateIsIssuerExternalCA(caReIssueInfo.getName());

            if (activeCertificate != null) {
                revokeCACertificate(caReIssueInfo, activeCertificate);
            }

        } catch (EntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + entityNotFoundException);
        }

    }

    private void revokeCACertificate(final CAReIssueInfo caReIssueInfo, final CertificateData activeCertificate) throws CertificateNotFoundException, EntityAlreadyExistsException,
            EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException,
            RootCertificateRevocationException, RevocationServiceException {

        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setIssuerDN(activeCertificate.getIssuerCertificate().getSubjectDN());
        dnBasedCertificateIdentifier.setSubjectDN(activeCertificate.getSubjectDN());
        dnBasedCertificateIdentifier.setCerficateSerialNumber(activeCertificate.getSerialNumber());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, caReIssueInfo.getRevocationReason(), caReIssueInfo.getInvalidityDate());
    }

    private CertificateData getCAActiveCertificate(final String caEntityName) throws CertificateNotFoundException {

        final List<CertificateData> certificateDatas = caCertificatePersistenceHelper.getCertificateDatas(caEntityName, CertificateStatus.ACTIVE);

        if (certificateDatas != null) {
            return certificateDatas.get(0);

        }
        return null;

    }

    private void checkCACanBeRevoked(final CAEntity caEntity) throws RootCertificateRevocationException {

        if (caEntity.getCertificateAuthority().isRootCA()) {
            if (caEntity.getCertificateAuthority().isIssuerExternalCA()) {
                logger.error("Root CA{}", caEntity.getCertificateAuthority().getName(), "cannot be revoked. Root CA is sub CA of External CA");
                systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager", "Root CA " + caEntity.getCertificateAuthority().getName()
                        + " cannot be revoked and is the SubCA of external CA", "RootCARevocation", ErrorSeverity.ERROR, "FAILURE");
                throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED);

            }
            logger.debug("Cannot revoke RootCA Certificate");
            systemRecorder.recordSecurityEvent("PkiManagerRevocationService", "RevocationManager", "Root CA " + caEntity.getCertificateAuthority().getName() + " can not be revoked",
                    "RootCARevocation", ErrorSeverity.ERROR, "FAILURE");
            throw new RootCertificateRevocationException(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED);
        }
    }

    /**
     * Generates ACTIVE keys and certificate for the CA Entity.
     * 
     * @param caEntity
     *            name of CA Entity.
     * @param reIssueType
     *            model that specifies certificate need to be generated for CA or CA with immediate Sub CAs or CA with all its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm does not exist in the database.
     * @throws CANotFoundException
     *             Thrown when given CA not found in the database.
     * @throws CertificateGenerationException
     *             Thrown when failure occurs generating the certificate for the CA Entity.
     * @throws CertificateServiceException
     *             Thrown in case any failure occurs with certificate generation.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public void rekeyCertificate(final String caEntityName, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException,
            RevokedCertificateException {

        try {

            final CAEntity caEntity = entityHelper.getCAEntity(caEntityName);

            rekeyHandler.rekeyCertificate(caEntity, reIssueType);

            // TORF-90825: Use for Roll back the certificate of internal root CA which is signed by external root CA to PKI selfsigned certificate.
            caCertificatePersistenceHelper.checkAndUpdateIsIssuerExternalCA(caEntityName);

        } catch (EntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + entityNotFoundException);
        }

    }

    /**
     * This method supports revoke with rekey operation of CA based on reIssueType.
     * 
     * <ul>
     * <li>If ReIssueType is CA then it will generate new keys and certificate for the given CA and revoke the invalid certificate</li>
     * <li>If ReIssueType is CA_WITH_IMMEDIATE_SUB_CAS then it will generate new keys and certificates of CA and its SubCAs and then revoke the invalid certificate of given CA.</li>
     * <li>If ReIssueType is CA_WITH_ALL_CHILD_CAS then it will generate new keys and certificates of CA and its hierarchy and then revoke the invalid certificate of given CA.</li>
     * </ul>
     * 
     * @param caReIssueInfo
     *            The caReIssueInfo object contains the CAName and revocation details.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateNotFoundException
     *             Thrown in case certificate does not exist for the given CA Entity.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown in case of Entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void rekeyCertificate(final CAReIssueInfo caReIssueInfo, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidInvalidityDateException, IssuerCertificateRevokedException, InvalidCAException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException, RootCertificateRevocationException, RevocationServiceException {

        try {

            final CAEntity caEntity = entityHelper.getCAEntity(caReIssueInfo.getName());
            final CertificateData activeCertificate = getCAActiveCertificate(caEntity.getCertificateAuthority().getName());

            checkCACanBeRevoked(caEntity);

            rekeyHandler.rekeyCertificate(caEntity, reIssueType);

            // TORF-90825: Use for Roll back the certificate of internal root CA which is signed by external root CA to PKI selfsigned certificate.
            caCertificatePersistenceHelper.checkAndUpdateIsIssuerExternalCA(caReIssueInfo.getName());

            if (activeCertificate != null) {
                revokeCACertificate(caReIssueInfo, activeCertificate);
            }

        } catch (EntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + entityNotFoundException);
        }

    }

    /**
     * Returns a list of certificates issued for the CAEntity or Entity based on CertificateStatus.
     * 
     * @param caEntityName
     *            The CA entity name.
     * @param certificateStatus
     *            The certificate status.
     * @return List of Certificate objects.
     * 
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity with corresponding status.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown when given Entity/CAEntity doesn't exists.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity is invalid.
     */
    public List<Certificate> listCertificates(final String caEntityName, final CertificateStatus... certificateStatus) throws CertificateNotFoundException, CertificateServiceException,
            EntityNotFoundException, InvalidEntityAttributeException {

        if (entityHelper.isCAEntityNameAvailable(caEntityName)) {
            throw new EntityNotFoundException("Entity not found with Name: " + caEntityName);
        }

        try {
            final List<Certificate> certificates = caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_1, certificateStatus);
            if (certificates == null) {
                throw new CertificateNotFoundException("No " + Arrays.toString(certificateStatus) + " certificate found");
            }
            return certificates;
        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        } catch (CertificateException | IOException exception) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, exception.getMessage());
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR + exception);
        }
    }

    /**
     * This method is used to update publish flag in DB in case Publish API is being called. Also this method dispatches event to Trust Distribution Service to publish certificate to Trust
     * distribution service.
     * 
     * @param entityName
     *            publish flag for this entity will be set either to true or false in DB
     * 
     * @throws CANotFoundException
     *             is thrown in case CAEntity is not found
     * @throws CertificateServiceException
     *             is thrown in case of any internal DB errors
     */
    public void publishCertificate(final String entityName) throws CANotFoundException, CertificateServiceException {

        try {
            final List<Certificate> certificates = getActiveInActiveCertificates(entityName);

            if (certificates == null) {
                throw new CertificateServiceException(ErrorMessages.CA_CERTIFICATES_NOT_FOUND);
            }

            // This is used here to set Issuer and Subject for ExtCertificate for existing certificates in the system.
            extCACertificatePersistanceHandler.updateIssuerAndSubjectForExtCertificate(entityName, certificates);
            tdpsPersistenceHandler.updateEntityData(entityName, EntityType.CA_ENTITY, true);
            certificateEventNotifier.notify(EntityType.CA_ENTITY, entityName, TDPSPublishStatusType.PUBLISH, certificates);
        } catch (PersistenceException | CertificateException | IOException exception) {
            CertificateServiceExceptionUtil.throwCertificateServiceException(exception);
        }
    }

    /**
     * This method is used to update publish flag in DB in case Publish API is being called. Also this method dispatches event to Trust Distribution Service to unpublish certificate from Trust
     * distribution service.
     * 
     * @param entityName
     *            publish flag for this entity will be set either to true or false in DB
     * 
     * @throws CANotFoundException
     *             is thrown in case CAEntity is not found
     * @throws CertificateServiceException
     *             is thrown in case of any internal DB errors
     */
    public void unPublishCertificate(final String entityName) throws CANotFoundException, CertificateServiceException {
        try {
            final List<Certificate> certificates = getActiveInActiveCertificates(entityName);

            if (certificates == null) {
                throw new CertificateServiceException(ErrorMessages.CA_ACTIVE_CERTIFICATE_NOT_FOUND);
            }

            tdpsPersistenceHandler.updateEntityData(entityName, EntityType.CA_ENTITY, false);
            certificateEventNotifier.notify(EntityType.CA_ENTITY, entityName, TDPSPublishStatusType.UNPUBLISH, certificates);
        } catch (PersistenceException | CertificateEncodingException | EntityServiceException exception) {
            CertificateServiceExceptionUtil.throwCertificateServiceException(exception);
        }
    }

    private List<Certificate> getActiveInActiveCertificates(final String entityName) throws CANotFoundException, CertificateServiceException {
        List<Certificate> activeAndInactiveCertificates;

        try {
            final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntity(entityName);

            if (!caEntityData.isExternalCA()) {
                activeAndInactiveCertificates = caCertificatePersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

            } else {
                activeAndInactiveCertificates = extCACertificatePersistanceHandler.getCertificatesForExtCA(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
            }
        } catch (CertificateException | IOException | PersistenceException exception) {
            throw new CertificateServiceException(exception);
        } catch (EntityServiceException entityServiceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, entityServiceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, entityServiceException);
        }

        return activeAndInactiveCertificates;
    }

    /**
     * Returns list of entities certificates {@link CertificateInfo} issued for a given caEntityName, Serial Number and entity certificate status.
     * 
     * @param caCertIdentifier
     *            is the CA certificate information holder containing CA name and Certificate serial number.
     * 
     * @param status
     *            Fetch the entity certificates which matches the list of {@link CertificateStatus} values
     * 
     * @return list of {@link CertificateInfo} objects
     * 
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given caentity name with corresponding Entity certificate Status.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws MissingMandatoryFieldException
     *             is thrown if the invalid attribute in the {@link CACertificateIdentifier}.
     */
    public List<CertificateInfo> listIssuedCertificates(final CACertificateIdentifier caCertificateIdentifier, final CertificateStatus... status) throws CANotFoundException,
            CertificateNotFoundException, CertificateServiceException, MissingMandatoryFieldException {

        logger.debug("Retrieving certificates List Issued By CA Name {} , Serial Number {} and  status {} ", caCertificateIdentifier.getCaName(), caCertificateIdentifier.getCerficateSerialNumber(),
                status);

        try {
            certificateValidator.validateCACertificateIdentifier(caCertificateIdentifier, status);

            final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntityData(caCertificateIdentifier.getCaName(), caCertificateIdentifier.getCerficateSerialNumber());
            if (caEntityData == null) {
                throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND);
            }

            final Set<CertificateData> certificateDatas = caEntityData.getCertificateAuthorityData().getCertificateDatas();

            certificateValidator.validateCACertificateIdentifier(caCertificateIdentifier, certificateDatas.size());

            // TODO : TORF-96916 - Investigating the best Approach between using JPA entities in persistant layer and across the entire layer
            final CertificateData certificateData = certificateHelper.getMappedCertificateData(certificateDatas, caCertificateIdentifier.getCerficateSerialNumber());

            if (certificateData == null) {
                throw new CertificateNotFoundException(ErrorMessages.CA_CERTIFICATE_NOT_FOUND);
            }
            final Long[] issuerCertificateIds = new Long[] { certificateData.getId() };

            final List<CertificateInfo> certificateInfoList = certificatePersistenceHelper.getCertificatesInfoByIssuerCA(issuerCertificateIds, status);

            return certificateInfoList;
        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }
    }

    /**
     * Returns list of entities corresponding certificates issued by particular {@link DNBasedCertificateIdentifier} and entity certificate status.
     * 
     * @param dnBasedCertIdentifier
     *            contains subjectDn,issuerDn and serialNumber.
     * 
     * @param status
     *            The list of {@link CertificateStatus} values for which Entity Certificates have to be listed
     * 
     * @return list of entities corresponding certificates {@link CertificateInfo} for the given {@link DNBasedCertificateIdentifier} and status.
     * 
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateNotFoundException
     *             Thrown if certificates not found for the given caEntityName with corresponding Certificate status.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws MissingMandatoryFieldException
     *             is thrown if the invalid attribute in the {@link DNBasedCertificateIdentifier}.
     */
    public List<CertificateInfo> listIssuedCertificates(final DNBasedCertificateIdentifier dNBasedIdentifier, final CertificateStatus... status) throws CertificateNotFoundException,
            CertificateServiceException, CANotFoundException, MissingMandatoryFieldException {

        logger.debug("Retrieving certificates List Issued Based on dnBasedCertificateIdentifier {} and  status {} ", dNBasedIdentifier, status);

        try {
            if (status == null || status.length == 0) {
                throw new MissingMandatoryFieldException(ErrorMessages.CERTIFICATE_STATUS_MANDATORY);
            }
            certificateValidator.validateDNBasedCertificateIdentifier(dNBasedIdentifier);

            final Long cAEntitiesCount = caCertificatePersistenceHelper.getCAEntitiesCount(dNBasedIdentifier);

            certificateValidator.validateDNBasedCertificateIdentifier(dNBasedIdentifier, cAEntitiesCount);

            final Long[] issuerCertificateIds = certificatePersistenceHelper.getCertificates(dNBasedIdentifier);
            if (issuerCertificateIds.length == 0) {
                throw new CertificateNotFoundException(ErrorMessages.CA_CERTIFICATE_NOT_FOUND);
            }

            final List<CertificateInfo> certificateInfoList = certificatePersistenceHelper.getCertificatesInfoByIssuerCA(issuerCertificateIds, status);

            return certificateInfoList;
        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }
    }

    /**
     * Returns CSR {@link PKCS10CertificationRequestHolder} for the given Root CA Entity Name.
     * 
     * @param rootCAName
     *            Name of the Root CA Entity for which CSR needs to be generated.
     * @param newKey
     *            If newKey flag is set to true, then CSR is generated using a new KeyPair.
     * @return {@link PKCS10CertificationRequestHolder}
     * @throws AlgorithmNotFoundException
     *             Thrown when the Algorithm is not found
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateRequestGenerationException
     *             Thrown when CertificateRequest generation or export is failed.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws InvalidCAException
     *             Thrown when the given CA is not active.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     */
    public PKCS10CertificationRequestHolder generateCSR(final String rootCAName, final boolean newKey) throws AlgorithmNotFoundException, CANotFoundException, CertificateRequestGenerationException,
            CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {

        logger.debug("Export CSR for Root CA {} " , rootCAName);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = generateCSRHandler.generateCSR(rootCAName, newKey);

        return pkcs10CertificationRequestHolder;
    }

    /**
     * This method is used to fetch latest CSR for the given CA from the database.
     * 
     * @param caName
     *            for which latest CSR has to be fetched.
     * @return CSR in PKCS10CertificationRequestHolder object.
     * 
     * @throws CertificateRequestGenerationException
     *             is thrown when internal error occurs while fetching csr.
     * @throws CertificateServiceException
     *             is thrown when internal db error occurs while fetching csr.
     * @throws InvalidOperationException
     *             Thrown when the certificateGenerationInfo is not found.
     */
    public PKCS10CertificationRequestHolder getCSR(final String caName) throws CertificateRequestGenerationException, CertificateServiceException, InvalidOperationException {
        logger.debug("Export CSR for Root CA {} " , caName);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = generateCSRHandler.getCSR(caName);

        return pkcs10CertificationRequestHolder;
    }

    /**
     * Gets CAEntity for the given caname.
     * 
     * @param rootCAName
     *            for which caentity has to be fetched.
     * @return caEntity
     * @throws CANotFoundException
     *             is thrown if CA is not found in the database.
     * @throws CertificateServiceException
     *             is thrown if any database error occurs while fetching Entity data.
     */
    public CAEntity getRootCAEntity(final String rootCAName) throws CANotFoundException, CertificateServiceException {

        CAEntityData caEntityData = null;
        try {
            caEntityData = caCertificatePersistenceHelper.getCAEntity(rootCAName);
        } catch (EntityServiceException entityServiceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, entityServiceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, entityServiceException);
        } catch (CANotFoundException caNotFoundException) {
            logger.error(ErrorMessages.ROOT_CA_NOT_FOUND, caNotFoundException.getMessage());
            systemRecorder.recordError("PKI_MANAGER.EXPORT_CSR_FAIL", ErrorSeverity.ERROR, "ExportCSRHandler", "ExportCSR", ErrorMessages.ROOT_CA_NOT_FOUND);
            throw new CANotFoundException(ErrorMessages.ROOT_CA_NOT_FOUND, caNotFoundException);
        }

        final CAEntity caEntity = caEntityMapper.toAPIFromModel(caEntityData);

        return caEntity;
    }

}
