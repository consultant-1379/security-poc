/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.CertificateRequestParser;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.SecGwCertificatePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.*;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.custom.secgw.SecGWCertificates;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

/**
 * This class contains the methods to create and update the entity for Security Gateway certificate, generate the Certificate and to get the
 * trusted CA certificates for Security Gateway.
 *
 * @author xlakdag
 */
public class SecGwCertificateManager {

    @Inject
    Logger logger;

    @Inject
    EntityHelper entityHelper;

    @Inject
    EntityCertificateManager entityCertificateManager;

    @Inject
    ValidationService validationService;

    @Inject
    ValidationServiceUtils validateServiceUtils;

    @Inject
    SecGwCertificatePersistenceHandler secGwPersistanceHandler;

    @Inject
    private EntitiesManager entitiesManager;

    @Inject
    private SystemRecorder systemRecorder;

    public static final String SECGW_DEFAULT_ENTITY_PROFILE = "SecGw_SAN_EP";
    public static final String SECGW_DEFAULT_ENTITY_CATEGORY_NAME = "SEC-GW";

    /**
     * Generate certificate for SecGW with CSR as input and to get required trusted certificates.
     *
     * @param entityName
     *            The entity name.
     * @param certificateRequest
     *            The CSR containing either PKCS10/CRMF request.
     * @param isChainRequired
     *            To check whether the chain is required for generated certificate
     * @param requestType
     *            type of the certificate request.
     * @return SecGWCerificates The list of secgw certificates and its trusted certificates
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityAlreadyExistsException
     *             Thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             Thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws EntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws IllegalArgumentException
     *             Thrown if the given CSR has unsupported fields.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidCertificateRequestException
     *             Thrown to indicate that the given Certificate Request is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid entity Attribute.
     * @throws InvalidEntityCategoryException
     *             Thrown when the given category is in invalid format.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid profile Attribute is found while mapping Entity
     * @throws InvalidProfileException
     *             Thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             Thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             Thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             Thrown when any mandatory fields are not given
     * @throws ProfileNotFoundException
     *             Thrown if given entity contains the entity profile that doesn't exists.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public SecGWCertificates generateSecGwCertificate(final String entityName, final CertificateRequest certificateRequest,
            final Boolean isChainRequired, final RequestType requestType) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException,
            EntityException, EntityServiceException, ExpiredCertificateException, IllegalArgumentException, InvalidCAException,
            InvalidCertificateRequestException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidEntityException,
            InvalidProfileAttributeException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException,
            MissingMandatoryFieldException, ProfileNotFoundException, RevokedCertificateException {

        createOrUpdateEntityForSecGw(entityName, certificateRequest);

        final Certificate secGwCertificate = entityCertificateManager.generateCertificate(entityName, certificateRequest, requestType);
        CertificateChain chainCertificates = null;
        if (isChainRequired) {
            chainCertificates = entityCertificateManager.getCertificateChain(entityName, EntityType.ENTITY,
                    Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE).get(0);
        }
        final List<Certificate> trustedCertificates = getTrustCertificatesForSecGw(entityName, CertificateStatus.ACTIVE);

        final SecGWCertificates secGwCertificates = new SecGWCertificates();
        secGwCertificates.setCertificate(secGwCertificate);
        secGwCertificates.setCertificateChain(chainCertificates);
        secGwCertificates.setTrustedCertificates(trustedCertificates);

        return secGwCertificates;
    }

    private List<Certificate> getTrustCertificatesForSecGw(final String entityName, final CertificateStatus... certificateStatuses)
            throws CertificateServiceException, EntityNotFoundException, ExternalCredentialMgmtServiceException, InvalidCAException,
            InvalidEntityAttributeException, ProfileNotFoundException {

        logger.info("Retrieving trust certificates for the SecGW entity name {}", entityName);
        final Set<Certificate> trustCertificates = new LinkedHashSet<Certificate>();

        final Entity entity = entityHelper.getEntity(entityName);

        final List<TrustProfile> trustProfileList = entity.getEntityProfile().getTrustProfiles();

        if (trustProfileList.isEmpty()) {
            systemRecorder.recordSecurityEvent("PKIManager.CertificateMangement", "SecGWCertificateManager",
                    "No Trust Profiles found in Entity Profile " + SECGW_DEFAULT_ENTITY_PROFILE,
                    "CERTIFICATEMANAGEMENT.GENERATE_SECGW_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "INFO");
            throw new ProfileNotFoundException(ErrorMessages.NO_TRUST_PROFILE_FOUND);
        }

        for (final TrustProfile trustProfile : trustProfileList) {
            trustCertificates.addAll(getInternalCACertificatesWithChain(trustProfile, certificateStatuses));
            trustCertificates.addAll(entityCertificateManager.getExternalCACertificates(trustProfile));
        }

        logger.info("Retrieved list of TrustCertificates for SecGW {}", trustCertificates.size());
        return new ArrayList<Certificate>(trustCertificates);
    }

    private void createOrUpdateEntityForSecGw(final String entityName, final CertificateRequest certificateRequest)
            throws AlgorithmNotFoundException, CertificateServiceException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityException, EntityServiceException, IllegalArgumentException, InvalidEntityAttributeException, InvalidEntityCategoryException,
            InvalidProfileAttributeException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException,
            MissingMandatoryFieldException, ProfileNotFoundException {

        try {
            final Entity entity = prepareEntityForSecGw(entityName, certificateRequest);
            OperationType opType = OperationType.CREATE;

            Entity existingEntity = null;
            try {
                existingEntity = entityHelper.getEntity(entityName);
            } catch (EntityNotFoundException entityNotFoundException) {
                logger.debug("No entity found with name " + entityName + " for security gateway with exception {}", entityNotFoundException);
            }
            //Set Operation type and entity id to update
            if (existingEntity != null) {
                opType = OperationType.UPDATE;
                entity.getEntityInfo().setId(existingEntity.getEntityInfo().getId());
            }
            final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(), opType, entity);
            validationService.validate(validateItem);

            if (existingEntity == null) {
                entitiesManager.createEntity(entity);
            } else {
                entitiesManager.updateEntity(entity);
            }
        } catch (CRLExtensionException | InvalidCRLGenerationInfoException | UnsupportedCRLVersionException exception) {
            logger.error("Entity creation for secgw failed with error {}", exception.getMessage());
            logger.debug("Entity creation for secgw failed with error {}", exception);
            throw new EntityException(exception.getMessage());
        }
    }

    private Entity prepareEntityForSecGw(final String entityName, final CertificateRequest certificateRequest) throws CANotFoundException,
            IllegalArgumentException, InvalidProfileAttributeException, InvalidProfileException, ProfileNotFoundException,
            ProfileServiceException, MissingMandatoryFieldException {

        final List<SubjectField> entitySubjectFields = getSubjectFieldsForSecGwEntity(certificateRequest);
        final Subject subject = new Subject();
        subject.setSubjectFields(entitySubjectFields);

        final SubjectAltName entitySubjectAltName = CertificateRequestParser.extractSubjectAltName(certificateRequest);

        final Entity entity = new Entity();

        final EntityCategory category = new EntityCategory();
        category.setModifiable(true);
        category.setName(SECGW_DEFAULT_ENTITY_CATEGORY_NAME);
        entity.setCategory(category);

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entityInfo.setSubject(subject);
        if (entitySubjectAltName != null) {
            entityInfo.setSubjectAltName(entitySubjectAltName);
        }
        entity.setEntityInfo(entityInfo);

        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(SECGW_DEFAULT_ENTITY_PROFILE);
        entity.setEntityProfile(entityProfile);

        return entity;
    }

    private List<SubjectField> getSubjectFieldsForSecGwEntity(final CertificateRequest certificateRequest) throws CANotFoundException,
            IllegalArgumentException, InvalidProfileAttributeException, InvalidProfileException, MissingMandatoryFieldException,
            ProfileNotFoundException, ProfileServiceException {

        final Set<SubjectFieldType> entityProfileSubjectFieldTypes = secGwPersistanceHandler.getSubjectFieldTypes(SECGW_DEFAULT_ENTITY_PROFILE);
        final List<SubjectField> subjectFields = CertificateUtils.getSubjectFieldsFromCertificateRequest(certificateRequest);
        final List<SubjectField> validSubjectFields = new ArrayList<SubjectField>();
        final List<SubjectFieldType> discardingSubjectFieldTypes = new ArrayList<SubjectFieldType>();
        for (final SubjectField subjectField : subjectFields) {
            final SubjectFieldType subjectFieldType = subjectField.getType();
            if (entityProfileSubjectFieldTypes.contains(subjectFieldType)) {
                validSubjectFields.add(subjectField);
            } else {
                discardingSubjectFieldTypes.add(subjectField.getType());
            }
        }
        if (discardingSubjectFieldTypes.size() > 0) {
            systemRecorder.recordSecurityEvent("PKIManager.CertificateMangement", "SecGWCertificateManager",
                    "Discarding the Subject Field Types" + discardingSubjectFieldTypes
                            + "in entity creation as those are not present in entity profile" + SECGW_DEFAULT_ENTITY_PROFILE,
                    "CERTIFICATEMANAGEMENT.GENERATE_SECGW_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "INFO");
        }
        return validSubjectFields;
    }

    private List<Certificate> getInternalCACertificatesWithChain(final TrustProfile trustProfile, final CertificateStatus... certificateStatuses)
            throws CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {

        final List<TrustCAChain> trustInternalCACertificateChains = trustProfile.getTrustCAChains();
        final List<Certificate> listOfTrustCertificates = new ArrayList<Certificate>();

        for (final TrustCAChain trustCAChain : trustInternalCACertificateChains) {
            final String internalCAName = trustCAChain.getInternalCA().getCertificateAuthority().getName();
            listOfTrustCertificates.addAll(entityCertificateManager.getCertificateChain(internalCAName, certificateStatuses));
        }
        return listOfTrustCertificates;
    }
}
