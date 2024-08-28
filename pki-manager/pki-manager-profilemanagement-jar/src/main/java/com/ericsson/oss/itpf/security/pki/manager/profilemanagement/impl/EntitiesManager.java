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

package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.InternetProtocolVersionType;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.EntityStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.AbstractEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAHierarchyPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityDetailsPeristenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.EntityNameUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.validator.OtpValidator;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.enrollment.EnrollmentURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyDeletedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPCountException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotDefinedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TDPSUrlInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntityDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.utils.EnrollmentInformationHandler;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.utils.TDPSURLBuilder;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * This class contains basic methods for Entity/CA Entity . List of methods implemented here are:
 * <ul>
 * <li>Creating entity</li>
 * <li>Updating entity</li>
 * <li>Retrieving entity</li>
 * <li>Bulk Retrieving entities</li>
 * <li>Deleting entity</li>
 * <li>Checking entity Name Availability</li>
 * </ul>
 *
 */
@SuppressWarnings("PMD.TooManyFields")
public class EntitiesManager {

    @Inject
    protected Logger logger;

    @Inject
    protected PersistenceManager persistenceManager;

    @Inject
    CoreEntitiesManager coreEntitiesManager;

    @Inject
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Inject
    EntityDetailsPeristenceHandler entityDetailsPeristenceHandler;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    ModelMapper entityMapper;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    ModelMapperv1 entityMapperv1;

    @Inject
    TDPSPersistenceHandler tDPSPersistenceHandler;

    @Inject
    TDPSURLBuilder tdpsURLBuilder;

    @Inject
    PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Inject
    CAHierarchyPersistenceHandler cAHeirarchyPersistenceHandler;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    ExtCertificateModelMapper extCertificateModelMapper;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntityPersistenceHandler<Entity> entityPersistenceHandler;

    @Inject
    private OtpValidator otpValidator;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private EnrollmentInformationHandler enrollmentInformationHandler;

    private static final String SPACE = " ";
    private static final String SPACE_IN_URL = "%20";

    /**
     * API for creating an entity of any type
     *
     * @param entity
     * @return {@link AbstractEntity}
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     */
    public <T extends AbstractEntity> T createEntity(T entity) throws EntityAlreadyExistsException, EntityServiceException, EntityNotFoundException,
            InvalidEntityAttributeException, InvalidEntityException {

        logger.debug("creating Entity {}", entity);

        final EntitiesPersistenceHandler<T> entitiesPersistenceHandler = (EntitiesPersistenceHandler<T>) getEntitiesPersistenceHandler(entity.getType());

        entity = entitiesPersistenceHandler.createEntity(entity);

        coreEntitiesManager.createEntity(entity);

        logger.debug(" Entity Created {}", entity);

        systemRecorder.recordEvent("ENTITYMANAGEMENT.CREATE_ENTITY", EventLevel.COARSE, "PKI", "PKIManager",
                " Entity [name = " + getEntityName(entity) + ", type = " + entity.getType() + " ] created successfully");

        return entity;
    }

    /**
     * API for updating an entity of any type
     *
     * @param entity
     * @return {@link AbstractEntity}
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws EntityNotFoundException
     *             thrown when given {@link Entity} doesn't exists in DB to update.
     * @throws EntityAlreadyExistsException
     *             thrown when trying to update an entity with name that already exists.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     */
    public <T extends AbstractEntity> T updateEntity(T entity) throws EntityServiceException, EntityNotFoundException, EntityAlreadyExistsException,
            CRLExtensionException, InvalidEntityAttributeException, InvalidEntityException {

        logger.debug("updating Entity {}", entity);

        final EntitiesPersistenceHandler<T> entitiesPersistenceHandler = (EntitiesPersistenceHandler<T>) getEntitiesPersistenceHandler(entity.getType());
        entity = entitiesPersistenceHandler.updateEntity(entity);

        coreEntitiesManager.updateEntity(entity);

        logger.debug("Entity Updated {}", entity);

        systemRecorder.recordEvent("ENTITYMANAGEMENT.UPDATE_ENTITY", EventLevel.COARSE, "PKI", "PKIManager",
                " Entity [name = " + getEntityName(entity) + ", type = " + entity.getType() + " ] updated successfully");

        return entity;
    }

    /**
     * API for updating entities
     *
     * @param entity
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws EntityAlreadyExistsException
     *             thrown when trying to update an entity with name that already exists.
     * @throws EntityNotFoundException
     *             thrown when given {@link Entity} doesn't exists in DB to update.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public void updateEntities(final Entities entities) throws CRLExtensionException, EntityServiceException, EntityNotFoundException,
            EntityAlreadyExistsException, InvalidEntityAttributeException, InvalidEntityException {

        logger.debug("updating Entities {}", entities);

        if (!ValidationUtils.isNullOrEmpty(entities.getEntities())) {
            for (final Entity entity : entities.getEntities()) {
                updateEntity(entity);
            }
        }

        if (!ValidationUtils.isNullOrEmpty(entities.getCAEntities())) {
            for (final CAEntity caEntity : entities.getCAEntities()) {
                updateEntity(caEntity);
            }
        }

        logger.debug("Entities Updated {}", entities);
    }

    /**
     * API for retrieving profiles of any type
     *
     * @param entityTypes
     *            Entity Type specifies the type of entities to be exported.It accepts variable arguments namely CAEntity and Entity .
     * @return list of {@link Entity}.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    public Entities getEntities(final EntityType... entityTypes) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {
        logger.debug("getEntities by type {} ", new Object[] { entityTypes });

        final List<EntityType> entityTypeList = Arrays.asList(entityTypes);
        final Entities pkiEntities = getEntitiesByType(entityTypeList);

        logger.debug("Entities Retrieved {}", pkiEntities);

        return pkiEntities;
    }

    /**
     * API for retrieving an entity based on Id/Name.
     *
     * @param entity
     *            instance {@link Entity} with Id/name set.
     * @return instance of {@link Entity} found in DB.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when EntityType other than CAEntity/Entity is given.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     */
    public <T extends AbstractEntity> T getEntity(T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        logger.debug("Retrieving Entity");

        final EntitiesPersistenceHandler<T> entitiesPersistenceHandler = (EntitiesPersistenceHandler<T>) getEntitiesPersistenceHandler(entity.getType());

        entity = entitiesPersistenceHandler.getEntity(entity);

        logger.debug("Entity Retrieved {}", entity);
        return entity;

    }

    /**
     * API for deleting an entity based on Id/Name.
     *
     * @param entity
     *            instance {@link Entity} with Id/name set.
     * @throws EntityAlreadyDeletedException
     *             thrown when given entity is already deleted.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any profile or is having any ongoing operation.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    public <T extends AbstractEntity> void deleteEntity(final T entity) throws EntityAlreadyDeletedException, EntityInUseException,
            EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        logger.debug("Deleting entity");

        final EntitiesPersistenceHandler<T> entitiesPersistenceHandler = (EntitiesPersistenceHandler<T>) getEntitiesPersistenceHandler(entity.getType());

        if (entitiesPersistenceHandler.isDeletable(entity)) {
            coreEntitiesManager.deleteEntity(entity);
            entitiesPersistenceHandler.deleteEntity(entity);
        }

        logger.debug("Entity Deleted");

        systemRecorder.recordEvent("ENTITYMANAGEMENT.DELETE_ENTITY", EventLevel.COARSE, "PKI", "PKIManager",
                " Entity [name = " + getEntityName(entity) + ", type = " + entity.getType() + " ] deleted successfully");

    }

    /**
     * API for deleting entities based on Id/Name.
     *
     * @param entities
     *            instance {@link Entities} with Id/name set.
     * @throws EntityAlreadyDeletedException
     *             thrown when given entity is already deleted.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any profile or is having any ongoing operation.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    public void deleteEntites(final Entities entities) throws EntityAlreadyDeletedException, EntityInUseException, EntityServiceException,
            EntityNotFoundException, InvalidEntityException, InvalidEntityAttributeException {
        logger.debug("Deleting entities");

        if (!ValidationUtils.isNullOrEmpty(entities.getEntities())) {
            for (final Entity entity : entities.getEntities()) {
                deleteEntity(entity);
            }
        }

        if (!ValidationUtils.isNullOrEmpty(entities.getCAEntities())) {
            for (final CAEntity caEntity : entities.getCAEntities()) {
                deleteEntity(caEntity);
            }
        }

        logger.debug("Entities Deleted");

    }

    /**
     * API for checking the profile name availability
     *
     * @param name
     *            Name to be checked for availability.
     * @param entityType
     *            {@link EntityType} in which name to be checked.
     * @return true/false
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when EntityType is other than caentity/entity.
     */
    public boolean isNameAvailable(final String name, final EntityType entityType) throws EntityServiceException, InvalidEntityException {
        logger.debug("availability of name in trust profiles {}", name);

        return getEntitiesPersistenceHandler(entityType).isNameAvailable(name.trim());
    }

    public EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler(final EntityType entityType) throws InvalidEntityException {
        final EntitiesPersistenceHandler<? extends AbstractEntity> entitiesPersistenceHandler = entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(entityType);
        return entitiesPersistenceHandler;
    }

    /**
     * Used to get Enrollmentinfo in case of SCEP and CMPV2. This method get the complete Entity object using the Entity name and passes that to the handler class to compute other details of
     * EnrollmentInfo.
     *
     * @param enrollmentType
     *            Type of enrollment.Can be SCEP or CMPV2.
     * @param entity
     *            Object of entity with required fields filled.
     * @return EnrollementInfo Object containing the CACertificate,EnrollmentURL and TrustDistributionURL.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             Thrown when there are any DB Errors retrieving the Entity Data.
     * @throws EnrollmentURLNotFoundException
     *             thrown when LoadBalancerAddress is not retrieved from the model
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0 to inform CREDM that the existing OTP is no longer valid.
     */
    public EnrollmentInfo getEnrollmentInfoForEntity(final Entity entity, final EnrollmentType enrollmentType) throws EntityNotFoundException,
            EnrollmentURLNotFoundException, EntityServiceException, InvalidEntityAttributeException, InvalidEntityException, OTPExpiredException {

        logger.debug("Entering method getEnrollmentInfoForEntity of class EntitiesManager ");
        final Entity entityFound = getEntity(entity);

        if (entityFound == null) {
            throw new EntityNotFoundException("Entity" + ProfileServiceErrorCodes.NOT_FOUND);
        }

        if (entityFound.getEntityInfo().getOTPCount() <= 0) {
            throw new OTPExpiredException(ProfileServiceErrorCodes.EXPIRED_OTP);
        }

        logger.debug("End of method getEnrollmentInfoForEntity of class EntitiesManager ");
        return enrollmentInformationHandler.getEnrollmentInformation(entityFound, enrollmentType);

    }

    /**
     * This method is used to get OTP.
     *
     * @param entityName
     *            Name of the entity for which OTP is to be retrieved.
     * @return otp
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     */
    public String getOtp(final Entity entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException {
        logger.info("Entering method getOtp of class EntitiesManager ");
        final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(entity.getType());
        final String otp = entityPersistenceHandler.getOtp(entity);
        logger.info("Leaving method getOtp of class EntitiesManager ");
        return otp;
    }

    private Entities getEntitiesByType(final List<EntityType> entityTypes) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final Entities pkiEntities = new Entities();

        for (final EntityType entityType : entityTypes) {
            switch (entityType) {
            case CA_ENTITY:
                pkiEntities.setCAEntities(getEntitiesPersistenceHandler(entityType).getEntities(entityType).getCAEntities());
                break;

            case ENTITY:
                pkiEntities.setEntities(getEntitiesPersistenceHandler(entityType).getEntities(entityType).getEntities());
                break;

            default:
                throw new InvalidEntityException(ProfileServiceErrorCodes.UNKNOWN_ENTITYTYPE);
            }
        }

        return pkiEntities;
    }

    /**
     * This method fetches the list of entities based on category
     *
     * @param entityCategory
     * @param isIssuerDataRequired
     *        if false, then issuer certificates data is not retrieved
     * @return List of entities based on category
     * @throws EntityCategoryNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityCategoryException
     *             thrown when the given entity category is invalid.
     */
    public List<Entity> getEntitiesByCategory(final EntityCategory entityCategory, final Boolean isIssuerDataRequired)
            throws EntityCategoryNotFoundException, EntityServiceException, EntityNotFoundException, InvalidEntityCategoryException, InvalidEntityException {

        final EntitiesPersistenceHandler<Entity> entitiesPersistenceHandler = (EntitiesPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
        return entitiesPersistenceHandler.getEntitiesByCategory(entityCategory, isIssuerDataRequired);
    }

    /**
     * This method fetches the list of entities based on category
     *
     * @param entityCategory
     * @return List of entities based on category
     * @throws EntityCategoryNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityCategoryException
     *             thrown when the given entity category is invalid.
     */
    public List<Entity> getEntitiesSummaryByCategory(final EntityCategory entityCategory)
            throws EntityCategoryNotFoundException, EntityServiceException, EntityNotFoundException, InvalidEntityCategoryException, InvalidEntityException {

        final EntitiesPersistenceHandler<Entity> entitiesPersistenceHandler = (EntitiesPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
        return entitiesPersistenceHandler.getEntitiesSummaryByCategory(entityCategory);
    }

    /**
     * This method fetches the list of entities of given entity type, based on given entity status.
     *
     * @param entityType
     *            the type of entity
     * @param entityStatus
     *            the status of entity
     * @return List of entities based on entity status
     */
    public <T extends AbstractEntity> List<T> getEntitiesByStatus(final EntityType entityType, final int entityStatus)
            throws EntityServiceException, EntityNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException, InvalidEntityException {

        final EntitiesPersistenceHandler<T> entitiesPersistenceHandler = (EntitiesPersistenceHandler<T>) getEntitiesPersistenceHandler(entityType);
        return entitiesPersistenceHandler.getEntitiesByStatus(entityStatus);
    }

    public List<Entity> getEntitiesWithInvalidCertificate(final Date notAfter, final int maxEntities, final EntityCategory... entityCategories)
            throws MissingMandatoryFieldException, EntityCategoryNotFoundException, EntityServiceException, InvalidEntityAttributeException, InvalidEntityException {

        final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
        return entityPersistenceHandler.getEntitiesWithInvalidCertificate(notAfter, maxEntities, entityCategories);
    }

    // TORF-57958 BEGIN
    /**
     * This method is used to get EntityName By IssuerName And SerialNumber.
     *
     * @param IssuerName
     *            Name of the issuer.
     * @param SerialNumber
     *            SerialNumber of the certificate
     * @return EntityName Name of the Entity
     * @throws CANotFoundException
     *             thrown when given issuer doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws SerialNumberNotFoundException
     *             thrown when given SerialNumber doesn't exist.
     */
    public String getEntityNameByCaNameAndSerialNumber(final String caName, final String serialNumber)
            throws CANotFoundException, EntityServiceException, InvalidEntityException, SerialNumberNotFoundException {
        String entityName;
        try {
            final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
            entityName = entityPersistenceHandler.getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        } catch (final PersistenceException exception) {
            logger.error("Exception while retrieving entity name", exception);
            throw new EntityServiceException(ProfileServiceErrorCodes.INTERNAL_ERROR);
        } catch (final SerialNumberNotFoundException serialNumberNotFoundException) {
            logger.error("Exception while retrieving entity name", serialNumberNotFoundException);
            throw new SerialNumberNotFoundException("Exception while retrieving entity name" + serialNumberNotFoundException.getMessage());
        } catch (final CANotFoundException caNotFoundException) {
            logger.error("Exception while retrieving entity name", caNotFoundException);
            throw new CANotFoundException("Exception while retrieving entity name" + caNotFoundException.getMessage());
        }
        return entityName;
    }

    /**
     * This method is used to get List of EntityName(s) By IssuerName.
     *
     * @param IssuerName
     *            Name of the issuer.
     * @return List of EntityName Names of the Entities signed by the selected issuer
     * @throws CANotFoundException
     *             thrown when given issuer doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */
    public List<String> getEntityNameListByIssuerName(final String caName) throws CANotFoundException, EntityServiceException, InvalidEntityException {
        List<String> entityNameList = new ArrayList<String>();
        try {
            final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
            entityNameList = entityPersistenceHandler.getEntityNameListByCaName(caName);
        } catch (final PersistenceException persistenceException) {
            logger.error("Exception while retrieving entity name", persistenceException);
            throw new EntityServiceException(ProfileServiceErrorCodes.INTERNAL_ERROR);
        } catch (final CANotFoundException caNotFoundException) {
            logger.error("Exception while retrieving entity name", caNotFoundException);
            throw new CANotFoundException("Exception while retrieving entity name" + caNotFoundException.getMessage());
        }
        return entityNameList;
    }

    /**
     * This method is used to get List of EntityName(s) By associated trustProfile.
     *
     * @param trustProfileName
     *            Name of the associated trust profile.
     * @return List of EntityName Names of the Entities signed by the selected issuer
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws ProfileNotFoundException
     *             thrown when given trustProfile doesn't exist.
     */
    public List<String> getEntityNameListByTrustProfileName(final String trustProfileName) throws EntityServiceException, InvalidEntityException, ProfileNotFoundException {
        List<String> entityNameList = new ArrayList<String>();
        try {
            final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
            entityNameList = entityPersistenceHandler.getEntityNameListByTrustProfile(trustProfileName);
        } catch (final PersistenceException persistenceException) {
            logger.error("Exception while retrieving entity name", persistenceException);
            throw new EntityServiceException(ProfileServiceErrorCodes.INTERNAL_ERROR);
        } catch (final ProfileNotFoundException profileNotFoundException) {
            logger.error("Exception while retrieving entity name", profileNotFoundException);
            throw new ProfileNotFoundException("Exception while retrieving entity name " + profileNotFoundException.getMessage());
        }
        return entityNameList;
    }

    /**
     * This method is used to get List of Entity(s) By IssuerName.
     *
     * @param IssuerName
     *            Name of the issuer.
     * @return List of Entity Entities signed by the selected issuer
     * @throws CANotFoundException
     *             thrown when given issuer doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */
    public List<Entity> getEntityListByIssuerName(final String caName) throws CANotFoundException, EntityServiceException, InvalidEntityException {
        List<Entity> entityList = null;
        try {
            final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
            entityList = entityPersistenceHandler.loadEntityListByCaName(caName);

        } catch (final PersistenceException persistenceException) {
            logger.error("Exception while retrieving entity", persistenceException);
            throw new EntityServiceException(ProfileServiceErrorCodes.INTERNAL_ERROR);
        } catch (final CANotFoundException caNotFoundException) {
            logger.error("Exception while retrieving entity", caNotFoundException);
            throw new CANotFoundException("Exception while retrieving entity" + caNotFoundException.getMessage());
        }
        return entityList;
    }

    // TORF-57958 END

    /**
     * This method validates and then updates OTP for an entity passed as a parameter.
     *
     * @param entity
     *            Name of the entity for which otp to be retrieved.
     * @throws EntityNotFoundException
     *             when the passed entity is not in the PKI-system i.e. ENtity is not present.
     * @throws EntityServiceException
     *             when there is any DB error while retrieving entity data.
     * @throws InvalidEntityException
     *             thrown when EntityType is other than caentity/entity.
     * @throws InvalidOTPCountException
     *             when OTPcount passed is exceeds 5 or is a negative number.
     * @throws InvalidOTPException
     *             when OTP passed is null.
     */
    public void updateOTP(final Entity entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidOTPCountException, InvalidOTPException {

        final String oTP = entity.getEntityInfo().getOTP().trim();
        final int oTPCount = entity.getEntityInfo().getOTPCount();
        final EntityPersistenceHandler<Entity> entityPersistenceHandler = ((EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(entity.getType()));

        if ((oTP == null || oTP.equals(Constants.EMPTY_STRING)) && oTPCount == 0) {
            entityPersistenceHandler.setOtp(entity);
            logger.info("OTP is Disabled");
            return;
        }

        if (oTP == null) {
            throw new InvalidOTPException(ProfileServiceErrorCodes.OTP_IS_NULL);
        }

        if (oTPCount == 0 || oTPCount < 0) {
            throw new InvalidOTPCountException(ProfileServiceErrorCodes.INVALID_OTP_COUNT);
        }

        if (oTPCount > Constants.OTP_DEFAULT_COUNT) {
            throw new InvalidOTPCountException(ProfileServiceErrorCodes.OTP_COUNT_EXCEEDED);
        }

        entityPersistenceHandler.setOtp(entity);
        logger.info("OTP is updated");

    }

    /**
     * This method returns TrustDistributionPoint URL
     *
     * @param entity
     *            for which TrustDistributionPoint URL
     * @param issuerName
     *            name of the issuer name for the entity
     * @param certificateStatus
     *            Whether the certificate is ACTIVE or INACTIVE
     * @return returns TrustDistributionPoint URL
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur
     * @throws TrustDistributionPointURLNotDefinedException
     *             thrown when TrustDistribution Publish Flag is not set.
     * @throws TrustDistributionPointURLNotFoundException
     *             thrown when TrustDistributionURL is not retrieved from TrustDistributionPointService.
     */
    public <T extends AbstractEntity> String getTrustDistributionPointUrl(final T entity, final String issuerName, final CertificateStatus certificateStatus)
            throws EntityNotFoundException, EntityServiceException, TrustDistributionPointURLNotDefinedException, TrustDistributionPointURLNotFoundException {

        String tDPSURL = null;
        final String ipv4TDPSSbLoadBalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv4, Constants.TDPS_PORT);

        if (ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadBalancerAddress)) {
            logger.error("SbLoadBalancer address is not configured for IPv4. This method only returns IPv4 Address. If required both IPv4 and Ipv6 use getTrustDistributionPointUrls() mtethod.");
            throw new TrustDistributionPointURLNotFoundException("SbLoadBalancer IPv4 " + ProfileServiceErrorCodes.HOST_NOT_FOUND);
        }

        try {
            final String serialNumber = getCertificateSerialNumber(entity, issuerName, certificateStatus);
            tDPSURL = getTDPSURL(entity, ipv4TDPSSbLoadBalancerAddress, serialNumber, issuerName, certificateStatus);
        } catch (CANotFoundException | CertificateNotFoundException certificateNotFoundException) {
            logger.error("Exception while retrieving TDPS URL", certificateNotFoundException);
            throw new TrustDistributionPointURLNotFoundException("Exception while retrieving TDPS URL" + certificateNotFoundException.getMessage());
        } catch (final CertificateServiceException e) {
            logger.error("Exception while retrieving TDPS URL", e);
            throw new EntityServiceException("Exception while retrieving TDPS URL" + e.getMessage());
        }
        return tDPSURL;
    }

    /**
     * This method returns CA Hierarchies for each root CA
     *
     * @return List of {@link TreeNode} object containing CA Hierarchies in tree format.
     * @throws CANotFoundException
     *             Throws when RootCA is not found or inactive in the system.
     * @throws EntityServiceException
     *             throws when any internal system error occurs while forming hierarchy.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public List<TreeNode<CAEntity>> getCAHierarchies() throws CANotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        logger.debug("EntitiesManager: Processing CA hierarchy for root CAs");

        final List<TreeNode<CAEntity>> cAHierarchies = cAHeirarchyPersistenceHandler.getRootCAHierarchies();

        logger.debug("EntitiesManager: Formed CA hierarchy for root CAs");

        return cAHierarchies;
    }

    /**
     * Get CA Hierarchy from given CA Name.
     *
     * @param entityName
     *            : name of the CA entity from which hierarchy need to be displayed.
     * @return TreeNode containing Hierarchy from given CA Entity
     * @throws EntityServiceException
     *             throws when any internal system error occurs while forming hierarchy.
     * @throws CANotFoundException
     *             thrown when no CA is present in Database with given name.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public TreeNode<CAEntity> getCAHierarchyByName(final String entityName) throws CANotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        logger.debug("EntitiesManager: Forming CA hierarchy for CA with name: {}", entityName);

        final TreeNode<CAEntity> cAHierarchy = cAHeirarchyPersistenceHandler.getCAHierarchyByName(entityName);

        logger.debug("EntitiesManager: Formed CA hierarchy for CA with name: {}", entityName);

        return cAHierarchy;
    }

    private <T extends AbstractEntity> String getTDPSURL(final T entity, final String host, final String serialNumber, final String issuerName, final CertificateStatus certificateStatus) {
        return getTDPSURL(EntityNameUtils.getName(entity), entity.getType(), host, serialNumber, issuerName, certificateStatus);
    }

    private <T extends AbstractEntity> String getTDPSURL(String entityName, final EntityType entityType, final String host, final String serialNumber, String issuerName,
            final CertificateStatus certificateStatus) {
        if (entityName.contains(SPACE)) {
            entityName = entityName.replace(SPACE, SPACE_IN_URL);
        }
        if (issuerName.contains(SPACE)) {
            issuerName = issuerName.replace(SPACE, SPACE_IN_URL);
        }
        return (new TDPSURLBuilder()).entityName(entityName).entityType(entityType.toString().toLowerCase()).host(host).serialNumber(serialNumber).issuerName(issuerName)
                .certificateStatus(certificateStatus.toString().toLowerCase()).build();
    }

    private <T extends AbstractEntity> String getCertificateSerialNumber(final T entity, final String issuerName, final CertificateStatus certificateStatus)
            throws CANotFoundException, CertificateNotFoundException, CertificateServiceException, EntityNotFoundException, TrustDistributionPointURLNotDefinedException {
        final String certificateSerialNumber;
        final Set<CertificateData> certificateDatas = tDPSPersistenceHandler.getCertificateDatas(entity);
        if (certificateDatas == null) {
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND);
        }

        certificateSerialNumber = extractSerialNumberFromCertificateData(certificateDatas, issuerName, certificateStatus);

        return certificateSerialNumber;
    }

    private String extractSerialNumberFromCertificateData(final Set<CertificateData> certificateDatas, final String issuerName, final CertificateStatus certificateStatus) {
        String certificateSerialNumber = null;

        for (final CertificateData certificateData : certificateDatas) {
            if (certificateData.getIssuerCA().getCertificateAuthorityData().getName().equals(issuerName) && certificateData.getStatus().intValue() == certificateStatus.getId()) {
                certificateSerialNumber = certificateData.getSerialNumber();
                break;
            }
        }

        return certificateSerialNumber;
    }

    /**
     * This method returns count of {@link CAEntity}/{@link Entity} that match with the given filter criteria
     *
     * @param entitiesFilter
     *            specifies criteria based on which entities have to be filtered
     * @return integer count of entities matching given criteria
     * @throws EntityServiceException
     *             Thrown when the internal db error occures while retreiving the entities.
     */
    public int getEntitiesCountByFilter(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        int count = 0;

        for (final EntityType entityType : entitiesFilter.getType()) {
            count += getEntitiesPersistenceHandler(entityType).getEntitiesCountByFilter(entitiesFilter);
        }

        return count;
    }

    /**
     * This method returns list of {@link CAEntity and @link Entity} that match with the given filter criteria and that lie between given offset, limit values.
     *
     * @param EntitiesFilter
     *            specifies criteria, offset, limit values based on which entities have to be filtered
     * @return list of entities between given offset, limit values matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public List<AbstractEntityDetails> getEntityDetailsByFilter(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        return entityDetailsPeristenceHandler.getEntityDetails(entitiesFilter);

    }

    /**
     * This method will returns the list of TrustedEntityInfos for a given entityType and entity Name to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     *
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     * @return list of TrustedEntityInfos for a given EntityType and entityName.
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     */
    public List<TrustedEntityInfo> getTrustedEntityInfosByTypeAndName(final EntityType entityType, final String entityName)
            throws CertificateNotFoundException, EntityNotFoundException, EntityServiceException, TrustDistributionPointURLNotFoundException {
        final List<TrustedEntityInfo> trustedEntityInfoList = new ArrayList<TrustedEntityInfo>();
        final List<CertificateData> certificateDatas;
        final List<CertificateData> publishToTDPSCertificateDatas = new ArrayList<CertificateData>();

        try {

            certificateDatas = tDPSPersistenceHandler.getCertificateDatas(entityType, entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

            if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
                throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND);
            }

            for (final CertificateData certificateData : certificateDatas) {
                if (certificateData.isPublishedToTDPS()) {
                    publishToTDPSCertificateDatas.add(certificateData);
                }
            }

            for (final CertificateData certificateDataForEntity : publishToTDPSCertificateDatas) {

                final CertificateData certificateData = certificateDataForEntity;

                final TrustedEntityInfo trustedEntityInfo = buildTrustedEntityInfoByData(entityType, entityName, certificateData);
                trustedEntityInfoList.add(trustedEntityInfo);
            }

        } catch (final PersistenceException exception) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, exception.getMessage());
            throw new EntityServiceException(ErrorMessages.UNEXPECTED_ERROR, exception);
        } catch (final CANotFoundException caNotFoundException) {
            logger.error(com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.CA_ENTITY_NOT_FOUND, caNotFoundException.getMessage());
            throw new EntityNotFoundException(com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.NO_ENTITY_FOUND, caNotFoundException);
        }
        return trustedEntityInfoList;
    }

    /**
     * This method will returns the list of TrustedEntityInfos for a given entityType and certificateStatus to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     * @param certificateStatus
     *            Certificate status could be ACTIVE.
     * @return list of TrustedEntityInfos for a given EntityType and CertificateStatus.
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     */
    public List<TrustedEntityInfo> getTrustedEntityInfosByTypeAndStatus(final EntityType entityType, final CertificateStatus... certificateStatuses)
            throws CertificateNotFoundException, EntityServiceException, InvalidEntityException, TrustDistributionPointURLNotFoundException {
        List<TrustedEntityInfo> trustedEntityInfoList = new ArrayList<TrustedEntityInfo>();
        Map<String, List<Certificate>> certificateInfoMap;

        try {
            certificateInfoMap = tDPSPersistenceHandler.getPublishedCertificates(entityType, certificateStatuses);
            trustedEntityInfoList = buildTrustedEntityInfos(entityType, certificateInfoMap);

        } catch (CertificateException | PersistenceException | IOException exception) {
            logger.error("Exception while retrieving published certificates", exception.getMessage());
            throw new EntityServiceException("Exception while retrieving published certificates", exception);
        }
        return trustedEntityInfoList;

    }

    private List<TrustedEntityInfo> buildTrustedEntityInfos(final EntityType entityType, final Map<String, List<Certificate>> certificateInfoMap)
            throws CertificateNotFoundException, TrustDistributionPointURLNotFoundException {
        final List<TrustedEntityInfo> trustedEntityInfoList = new ArrayList<TrustedEntityInfo>();

        if (ValidationUtils.isNullOrEmpty(certificateInfoMap)) {
            return trustedEntityInfoList;
        }

        for (final Map.Entry<String, List<Certificate>> certificateInfo : certificateInfoMap.entrySet()) {
            final List<TrustedEntityInfo> trustedEntityInfos = buildTrustedEntityInfos(entityType, certificateInfo.getKey(), certificateInfo.getValue());
            trustedEntityInfoList.addAll(trustedEntityInfos);
        }
        return trustedEntityInfoList;
    }

    private List<TrustedEntityInfo> buildTrustedEntityInfos(final EntityType entityType, final String entityName, final List<Certificate> certificates)
            throws CertificateNotFoundException, TrustDistributionPointURLNotFoundException {
        final List<TrustedEntityInfo> trustedEntityInfoList = new ArrayList<TrustedEntityInfo>();

        if (ValidationUtils.isNullOrEmpty(certificates)) {
            return trustedEntityInfoList;
        }

        for (final Certificate certificate : certificates) {
            final TrustedEntityInfo trustedEntityInfo = buildTrustedEntityInfo(entityType, entityName, certificate);
            trustedEntityInfoList.add(trustedEntityInfo);
        }

        return trustedEntityInfoList;
    }

    private TrustedEntityInfo buildTrustedEntityInfo(final EntityType entityType, final String entityName, final Certificate certificate)
            throws CertificateNotFoundException, TrustDistributionPointURLNotFoundException {

        final TrustedEntityInfo trustedEntityInfo = new TrustedEntityInfo();

        trustedEntityInfo.setCertificateSerialNumber(certificate.getSerialNumber());
        trustedEntityInfo.setCertificateStatus(certificate.getStatus());
        trustedEntityInfo.setEntityName(entityName);
        trustedEntityInfo.setEntityType(entityType);
        trustedEntityInfo.setIssuerDN(certificate.getIssuer().getName());

        final String subject = certificate.getSubject() != null ? certificate.getSubject().toASN1String() : Constants.EMPTY_STRING;
        trustedEntityInfo.setSubjectDN(subject);

        final String ipv4TDPSSbLoadbalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv4, Constants.TDPS_PORT);
        final String ipv6TDPSSbLoadbalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv6, Constants.TDPS_PORT);

        if (ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadbalancerAddress) && ValidationUtils.isNullOrEmpty(ipv6TDPSSbLoadbalancerAddress)) {
            logger.error("SbLoadBalancer addresses are not configured for both IPv4 and IPv6. Atleast one of them should configured");
            throw new TrustDistributionPointURLNotFoundException(ProfileServiceErrorCodes.HOST_NOT_FOUND);
        }

        if (!ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadbalancerAddress)) {
            final String ipv4TrustDistributionPointURL = getTDPSURL(entityName, entityType, ipv4TDPSSbLoadbalancerAddress, certificate.getSerialNumber(), certificate.getIssuer().getName(),
                    certificate.getStatus());
            trustedEntityInfo.setTrustDistributionPointURL(ipv4TrustDistributionPointURL);
            trustedEntityInfo.setIpv4TrustDistributionPointURL(ipv4TrustDistributionPointURL);
        }

        if (!ValidationUtils.isNullOrEmpty(ipv6TDPSSbLoadbalancerAddress)) {
            final String ipv6TrustDistributionPointURL = getTDPSURL(entityName, entityType, ipv6TDPSSbLoadbalancerAddress, certificate.getSerialNumber(), certificate.getIssuer().getName(),
                    certificate.getStatus());
            trustedEntityInfo.setIpv6TrustDistributionPointURL(ipv6TrustDistributionPointURL);
        }

        return trustedEntityInfo;
    }

    private TrustedEntityInfo buildTrustedEntityInfoByData(final EntityType entityType, final String entityName, final CertificateData certificateData)
            throws TrustDistributionPointURLNotFoundException {

        final TrustedEntityInfo trustedEntityInfo = new TrustedEntityInfo();

        trustedEntityInfo.setCertificateSerialNumber(certificateData.getSerialNumber());
        trustedEntityInfo.setCertificateStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        trustedEntityInfo.setEntityName(entityName);
        trustedEntityInfo.setEntityType(entityType);

        trustedEntityInfo.setIssuerDN(certificateData.getIssuerCA().getCertificateAuthorityData().getName());
        trustedEntityInfo.setSubjectDN(certificateData.getSubjectDN());
        if (certificateData.getIssuerCertificate() != null) {
            trustedEntityInfo.setIssuerFullDN(certificateData.getIssuerCertificate().getSubjectDN());
        } else {
            trustedEntityInfo.setIssuerFullDN(certificateData.getIssuerCA().getCertificateAuthorityData().getSubjectDN());
        }

        final String ipv4TDPSSbLoadbalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv4, Constants.TDPS_PORT);
        final String ipv6TDPSSbLoadbalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv6, Constants.TDPS_PORT);

        if (ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadbalancerAddress) && ValidationUtils.isNullOrEmpty(ipv6TDPSSbLoadbalancerAddress)) {
            logger.error("SbLoadBalancer addresses are not configured for both IPv4 and IPv6. Atleast one of them should configured");
            throw new TrustDistributionPointURLNotFoundException(ProfileServiceErrorCodes.HOST_NOT_FOUND);
        }

        if (!ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadbalancerAddress)) {
            final String ipv4TrustDistributionPointURL = getTDPSURL(entityName, entityType, ipv4TDPSSbLoadbalancerAddress, certificateData.getSerialNumber(),
                    certificateData.getIssuerCA().getCertificateAuthorityData().getName(), CertificateStatus.getStatus(certificateData.getStatus()));
            trustedEntityInfo.setTrustDistributionPointURL(ipv4TrustDistributionPointURL);
            trustedEntityInfo.setIpv4TrustDistributionPointURL(ipv4TrustDistributionPointURL);
        }

        if (!ValidationUtils.isNullOrEmpty(ipv6TDPSSbLoadbalancerAddress)) {
            final String ipv6TrustDistributionPointURL = getTDPSURL(entityName, entityType, ipv6TDPSSbLoadbalancerAddress, certificateData.getSerialNumber(),
                    certificateData.getIssuerCA().getCertificateAuthorityData().getName(), CertificateStatus.getStatus(certificateData.getStatus()));
            trustedEntityInfo.setIpv6TrustDistributionPointURL(ipv6TrustDistributionPointURL);
        }

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = CertificateUtils.convert(certificateData.getCertificate());
        } catch (final CertificateException | IOException exception) {
            logger.error("Exception while building x509 certificate", exception);
            throw new EntityServiceException("Exception while building x509 certificate", exception);
        }
        trustedEntityInfo.setX509Certificate(x509Certificate);

        return trustedEntityInfo;
    }

    /**
     * Method to persist CAEntityData/EntityData in Manager DB
     *
     * @param CAEntityData
     *            or EntityData
     * @param entityType
     * @return CAEntityData or EntityData
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is not of type caentity/entity.
     */
    public <E extends AbstractEntityData> E persistEntityData(final E entityData, final EntityType entityType) throws EntityAlreadyExistsException, EntityServiceException, InvalidEntityException {

        final AbstractEntityPersistenceHandler<AbstractEntity> entityPersistenceHandler = (AbstractEntityPersistenceHandler<AbstractEntity>) entitiesPersistenceHandlerFactory
                .getEntitiesPersistenceHandler(entityType);
        final E entity = entityPersistenceHandler.persistEntityData(entityData);

        return entity;
    }

    /**
     * Method used to create EntityInfo/CertificationAuthority
     *
     * @param CAEntity
     *            or Entity
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T extends AbstractEntity> void validateAndcreateCoreEntities(final List<T> validEntities) throws EntityAlreadyExistsException, EntityServiceException {
        coreEntitiesManager.createBulkEntities(validEntities);
    }

    /**
     * This method will returns the list of TrustProfilesName for a given CAentity.
     *
     * @param cAEntity
     *            Class of entity to be checked (CAEntity/Entity).
     * @return list of TrustProfiles name matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */

    public List<String> getTrustProfileNamesByExtCA(final CAEntityData caEntity) throws EntityServiceException, InvalidEntityException {
        logger.debug("Get Trust Profile by CAEntity Name");
        final CAEntityPersistenceHandler<CAEntity> entityPersistenceHandler = (CAEntityPersistenceHandler<CAEntity>) getEntitiesPersistenceHandler(EntityType.CA_ENTITY);
        return entityPersistenceHandler.getTrustProfileNamesWithUseAsExternalCAs(caEntity);
    }

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     *
     * @throws EntityStatusUpdateFailedException
     * @throws InvalidEntityException
     */
    public void updateEntityStatusToInactive() throws EntityStatusUpdateFailedException, InvalidEntityException {
        final CAEntityPersistenceHandler<CAEntity> caEntityPersistenceHandler = (CAEntityPersistenceHandler<CAEntity>) getEntitiesPersistenceHandler(EntityType.CA_ENTITY);
        caEntityPersistenceHandler.updateCAEntityStatusToInactive();
        final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
        entityPersistenceHandler.updateEntityStatusToInactive();
    }

    /**
     * This method is used in case of SCEP for validating OTP
     *
     * @param entityName
     *            Name of the entity for which otp to be validated.
     * @param otp
     *            is the challenge password of the CSR.
     * @return true/false
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             Thrown when there are any DB Errors retrieving the Entity Data.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0.
     */
    public boolean isOTPValid(final String entityName, final String otp) throws EntityNotFoundException, EntityServiceException, OTPExpiredException {
        logger.info("validating OTP inside class EntitiesManager ");
        return otpValidator.isOtpValid(entityName, otp);

    }

    private <T extends AbstractEntity> String getEntityName(final T entity) {
        String entityName = "";
        switch (entity.getType()) {
        case CA_ENTITY:
            final CAEntity caEntity = (CAEntity) entity;
            entityName = caEntity.getCertificateAuthority().getName();
            break;

        case ENTITY:
            final Entity endEntity = (Entity) entity;
            entityName = endEntity.getEntityInfo().getName();
            break;
        }
        return entityName;
    }

    /**
     * This method is used to return TDPSUrlInfo object which contains both IPv4 and IPv6 TDPS urls for the Certificate which is identified by the given entity, issuerName and certificateStatus.
     *
     * @param entity
     *            Entity for which TrustDistribution IPV4 and IPV6 URLs have to be returned.
     * @param issuerName
     *            IssuerName of the entity certificate for which TrustDistribution IPV4 and IPV6 URLs have to be returned.
     * @param certificateStatus
     *            Certificate status which could be either ACTIVE or INACTIVE.
     * @throws CANotFoundException
     *             when the given CA entity is not found.
     * @return TDPSUrlInfo object it contains IPv4 and IPv6 TDPS urls.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotDefinedException
     *             thrown when TrustDistribution Publish Flag is not set.
     * @throws TrustDistributionPointURLNotFoundException
     *             thrown when TrustDistributionURL is not retrieved for the certificate which is identified by the given entity, issuer name and certificate status.
     */
    public <T extends AbstractEntity> TDPSUrlInfo getTrustDistributionPointUrls(final T entity, final String issuerName, final CertificateStatus certificateStatus)
            throws EntityNotFoundException, EntityServiceException, TrustDistributionPointURLNotDefinedException, TrustDistributionPointURLNotFoundException {

        final TDPSUrlInfo tdpsUrlInfo = new TDPSUrlInfo();
        try {
            final String serialNumber = getCertificateSerialNumber(entity, issuerName, certificateStatus);

            final String ipv4TDPSSbLoadbalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv4, Constants.TDPS_PORT);
            final String ipv6TDPSSbLoadbalancerAddress = getTDPSSbLoadBalancerAddress(InternetProtocolVersionType.IPv6, Constants.TDPS_PORT);

            if (ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadbalancerAddress) && ValidationUtils.isNullOrEmpty(ipv6TDPSSbLoadbalancerAddress)) {
                logger.error("SbLoadBalancer addresses are not configured for both IPv4 and IPv6. Atleast one of them should configured");
                throw new TrustDistributionPointURLNotFoundException(ProfileServiceErrorCodes.HOST_NOT_FOUND);
            }

            if (!ValidationUtils.isNullOrEmpty(ipv4TDPSSbLoadbalancerAddress)) {
                final String ipv4Address = getTDPSURL(entity, ipv4TDPSSbLoadbalancerAddress, serialNumber, issuerName, certificateStatus);
                tdpsUrlInfo.setIpv4Address(ipv4Address);
            }

            if (!ValidationUtils.isNullOrEmpty(ipv6TDPSSbLoadbalancerAddress)) {
                final String ipv6Address = getTDPSURL(entity, ipv6TDPSSbLoadbalancerAddress, serialNumber, issuerName, certificateStatus);
                tdpsUrlInfo.setIpv6Address(ipv6Address);
            }
        } catch (CANotFoundException | CertificateNotFoundException certificateNotFoundException) {
            logger.error("Exception while retrieving TDPS URL", certificateNotFoundException);
            throw new TrustDistributionPointURLNotFoundException("Exception while retrieving TDPS URL" + certificateNotFoundException.getMessage());
        } catch (final CertificateServiceException e) {
            logger.error("Exception while retrieving TDPS URL", e);
            throw new EntityServiceException("Exception while retrieving TDPS URL" + e.getMessage());
        }

        return tdpsUrlInfo;
    }

    private String getTDPSSbLoadBalancerAddress(final InternetProtocolVersionType internetProtocolVersionType, final String port) {
        String sbLoadBalancerAddress = getSbLoadBalancerAddress(internetProtocolVersionType);

        if (!ValidationUtils.isNullOrEmpty(sbLoadBalancerAddress)) {
            sbLoadBalancerAddress += Constants.COLON_OPERATOR + port;
        }

        return sbLoadBalancerAddress;
    }

    private String getSbLoadBalancerAddress(final InternetProtocolVersionType internetProtocolVersionType) {
        String sbLoadBalancerAddress = null;

        switch (internetProtocolVersionType) {
        case IPv4:
            sbLoadBalancerAddress = pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address();
            break;
        case IPv6:
            sbLoadBalancerAddress = pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address();
            break;
        default:
            logger.error("unsupported Internet Protocol Version type {}", internetProtocolVersionType);
        }

        return sbLoadBalancerAddress;
    }

    /**
     * Returns id and name of CA Entities based on status provided and externalCARequired flag.
     *
     * @param caStatus
     *            status of CA Entity.
     * @param externalCARequired
     *            boolean externalCA.
     * @return list of id and name of CA Entities with status
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity type is other than caentity/entity.
     */
    public List<CAEntity> fetchCAEntitiesIdAndName(final CAStatus caStatus, final boolean externalCARequired) throws EntityServiceException, InvalidEntityException {
        final CAEntityPersistenceHandler<CAEntity> caEntityPersistenceHandler = (CAEntityPersistenceHandler<CAEntity>) getEntitiesPersistenceHandler(EntityType.CA_ENTITY);

        final List<CAEntity> caEntitiesList = caEntityPersistenceHandler.fetchCAEntitiesIdAndNameByStatus(caStatus, externalCARequired);
        return caEntitiesList;
    }

    /**
     * This method is get entity based on entity name, subject DN and issuer DN
     *
     * @param entitySubjectDN
     *            Subject DN of the entity
     * @param issuerDN
     *            Issuer DN
     * @return {@link Entity} that is retrieved successfully.
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity type is other than caentity/entity.
     */
    public Entity getEntity(final String entitySubjectDN, final String issuerDN) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException {

        final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
        return entityPersistenceHandler.getEntity(entitySubjectDN, issuerDN);
    }

    /**
     * @param createdEntity
     * @throws InvalidEntityException
     */
    public void validateSubject(final Entity createdEntity) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidSubjectException {
        final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) getEntitiesPersistenceHandler(EntityType.ENTITY);
        entityPersistenceHandler.validateSubject(createdEntity);
    }

    /**
     * This method is get Trusted Entity Info chain by entity type and entity name
     *
     * @param entityType
     *            type of entity ca/entity
     * @param entityName
     *            name of the entity
     * @param certificateStatus
     *            certificate status of the entity
     * @return list of TrustedEntityInfo
     * @throws CertificateNotFoundException
     *             thrown when the TDPS certificates are not found
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown when TDPS url not found
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     */
    public List<List<TrustedEntityInfo>> getTrustedEntityInfosChainByTypeAndName(final EntityType entityType, final String entityName, final CertificateStatus[] certificateStatus)
            throws CertificateNotFoundException, TrustDistributionPointURLNotFoundException, EntityServiceException, EntityNotFoundException {
        final List<List<TrustedEntityInfo>> trustedEntityInfoChainList = new ArrayList<List<TrustedEntityInfo>>();
        final List<CertificateData> certificateDatas;
        final List<CertificateData> publishToTDPSCertificateDatas = new ArrayList<CertificateData>();

        try {

            certificateDatas = tDPSPersistenceHandler.getCertificateDatas(entityType, entityName, certificateStatus);

            if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
                throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND);
            }

            for (final CertificateData certificateData : certificateDatas) {
                if (certificateData.isPublishedToTDPS()) {
                    publishToTDPSCertificateDatas.add(certificateData);
                }
            }

            for (final CertificateData certificateDataForEntity : publishToTDPSCertificateDatas) {

                CertificateData certificateData = certificateDataForEntity;
                final List<TrustedEntityInfo> trustedEntityInfoChain = new ArrayList<TrustedEntityInfo>();

                final TrustedEntityInfo trustedEntityInfo = buildTrustedEntityInfoByData(entityType, entityName, certificateData);
                trustedEntityInfoChain.add(trustedEntityInfo);

                while ((certificateData.getIssuerCertificate() != null) && (certificateData.getIssuerCertificate().getId() != certificateData.getId())) {
                    final CAEntityData issuerData = certificateData.getIssuerCA();

                    trustedEntityInfoChain.add(buildTrustedEntityInfoByData(EntityType.CA_ENTITY, issuerData.getCertificateAuthorityData().getName(), certificateData.getIssuerCertificate()));

                    certificateData = certificateData.getIssuerCertificate();
                }
                trustedEntityInfoChainList.add(trustedEntityInfoChain);
            }

        } catch (final PersistenceException exception) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, exception.getMessage());
            throw new EntityServiceException(ErrorMessages.UNEXPECTED_ERROR, exception);
        } catch (final CANotFoundException caNotFoundException) {
            logger.error(com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.CA_ENTITY_NOT_FOUND, caNotFoundException.getMessage());
            throw new EntityNotFoundException(com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.NO_ENTITY_FOUND, caNotFoundException);
        }
        return trustedEntityInfoChainList;

    }

    /**
     * Method to delete the entity from pki manager
     *
     * @param entityName
     *            name of the entity which should be deleted
     * @throws EntityAlreadyDeletedException
     *             thrown if entity is already deleted
     * @throws EntityInUseException
     *             thrown if the entity has valid certificates
     * @throws EntityNotFoundException
     *             thrown if the entity is not present in the db
     * @throws EntityServiceException
     *             thrown when internal db error occurs
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute
     */
    public <T extends AbstractEntity> void deletePkiManagerEntity(final String entityName)
            throws EntityAlreadyDeletedException, EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        logger.debug("Deleting entity");

        Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entity.setEntityInfo(entityInfo);

        entity = entityPersistenceHandler.getEntityForCertificateGeneration(entity);
        logger.debug("Retrieved Entity {}  ", entity);

        if (entityPersistenceHandler.isDeletable(entity)) {
            entityPersistenceHandler.deleteEntity(entity);
        }

        logger.debug("Entity Deleted");

    }

    /**
     * API for retrieving profiles of any type
     *
     * @param entityTypes
     *            Entity Type specifies the type of entities to be exported.It accepts variable arguments namely CAEntity and Entity .
     * @return list of {@link Entity}.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    public Entities getEntitiesForImport(final EntityType... entityTypes) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {
        logger.debug("getEntities by type {} ", new Object[] { entityTypes });

        final List<EntityType> entityTypeList = Arrays.asList(entityTypes);
        final Entities pkiEntities = getEntitiesByTypeforImport(entityTypeList);

        logger.debug("Entities Retrieved {}", pkiEntities);

        return pkiEntities;
    }

    /**
     * API for retrieving an entity used for import/update entity operation based on Id/Name.
     *
     * @param entity
     *            instance {@link Entity} with Id/name set.
     * @return instance of {@link Entity} found in DB.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when EntityType other than CAEntity/Entity is given.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     */
    public <T extends AbstractEntity> T getEntityForImport(T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        logger.debug("Retrieving Entity");

        final EntitiesPersistenceHandler<T> entitiesPersistenceHandler = (EntitiesPersistenceHandler<T>) getEntitiesPersistenceHandler(entity.getType());

        entity = entitiesPersistenceHandler.getEntityForImport(entity);

        logger.debug("Entity Retrieved {}", entity);
        return entity;

    }
    private Entities getEntitiesByTypeforImport(final List<EntityType> entityTypes) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final Entities pkiEntities = new Entities();

        for (final EntityType entityType : entityTypes) {
            switch (entityType) {
            case CA_ENTITY:
                pkiEntities.setCAEntities(getEntitiesPersistenceHandler(entityType).getEntitiesForImport(entityType).getCAEntities());
                break;

            case ENTITY:
                pkiEntities.setEntities(getEntitiesPersistenceHandler(entityType).getEntitiesForImport(entityType).getEntities());
                break;

            default:
                throw new InvalidEntityException(ProfileServiceErrorCodes.UNKNOWN_ENTITYTYPE);
            }
        }

        return pkiEntities;
    }

}
