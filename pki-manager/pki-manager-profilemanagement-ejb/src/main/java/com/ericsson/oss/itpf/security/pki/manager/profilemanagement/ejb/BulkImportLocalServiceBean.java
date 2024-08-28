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

package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import java.util.*;

import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

/**
 * This class will import bulk Entities in both Manager and Core. Entities can be Entity/CAEntity
 *
 * @author tcschsa
 *
 */
@Stateless
@LocalBean
public class BulkImportLocalServiceBean {

    @Inject
    private EntitiesManager entitiesManager;

    @Inject
    ValidationServiceUtils validateServiceUtils;

    @Inject
    ValidationService validationService;

    @Inject
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Inject
    EntitiesModelMapperFactory entitiesModelMapperFactory;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    private static final String FOR_ENTITY = ": in PKIManager for the Entity - ";

    /**
     * Method to import CAEntities/Entities
     *
     * @param entities
     * @return list of entities
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when given EntityProfile inside CA Entity/Entity doesn't exist or in inactive state.
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws InvalidCRLGenerationInfoExceptionR
     *             thrown if the CRLGenerationInfo Fields are invalid.
     */
    public <T extends AbstractEntity> List<AbstractEntity> importEntities(final Entities entities) throws AlgorithmNotFoundException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension,
            InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException, UnsupportedCRLVersionException, CRLExtensionException, InvalidCRLGenerationInfoException {

        final List<AbstractEntity> validEntities = validateAndCreateManagerEntities(getEntitiesList(entities));
        entitiesManager.validateAndcreateCoreEntities(validEntities);
        return validEntities;
    }

    private final List<AbstractEntity> validateAndCreateManagerEntities(final List<AbstractEntity> givenEntities) throws AlgorithmNotFoundException, EntityAlreadyExistsException,
            EntityCategoryNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException, UnsupportedCRLVersionException, CRLExtensionException,
            InvalidCRLGenerationInfoException {

        final List<AbstractEntityData> validManagerEntityData = new ArrayList<AbstractEntityData>();
        final Map<String, Long> entityNameAndIDMap = new HashMap<String, Long>();

        for (final AbstractEntity abstractEntity : givenEntities) {
            validManagerEntityData.add(getValidEntityData(abstractEntity));
        }

        persistManagerEntities(validManagerEntityData, entityNameAndIDMap);
        setIdToEntities(givenEntities, entityNameAndIDMap);
        return givenEntities;
    }

    /**
     * Method to validate CAEntity/Entity and map the CAEntity/Entity to JPA Model
     *
     * @return CAEntityData/EntityData
     *
     * @throws AlgorithmNotFoundException
     *             thrown when the given algorithm is not found.
     * @throws EntityAlreadyExistsException
     *             thrown when creating an entity that already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown to indicate category is not found.
     * @throws EntityServiceException
     *             thrown when the exceptions related to entity service occurs.
     * @throws InvalidEntityAttributeException
     *             thrown when invalid entity attribute is provided as part of the request.
     * @throws InvalidEntityCategoryException
     *             thrown to indicate that category name is in invalid format.
     * @throws InvalidProfileException
     *             thrown when the given profile is invalid.
     * @throws InvalidSubjectAltNameExtension
     *             thrown when the invalid subject alt name is provided as part of the extension.
     * @throws InvalidSubjectException
     *             thrown when the invalid subject is provided as part of the request.
     * @throws MissingMandatoryFieldException
     *             thrown when the mandatory field is missed as part of the request.
     * @throws ProfileNotFoundException
     *             thrown when given Profile doesn't exists or in inactive state.
     * @throws UnsupportedCRLVersionException
     *             thrown if the Unsupported CRL Version is found.
     * @throws CRLExtensionException
     *             thrown for Invalid CRL Extension.
     * @throws InvalidCRLGenerationInfoException
     *             thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     *
     */
    private <T extends AbstractEntity> AbstractEntityData getValidEntityData(final T entity) {

        final EntityType entityType = entity.getType();
        try {
            final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entityType, OperationType.CREATE, entity);
            validationService.validate(validateItem);

            final ModelMapper entitiesMapper = entitiesModelMapperFactory.getEntitiesMapper(entityType);
            logger.debug(" Entity Created {}", entity);
            return entitiesMapper.fromAPIToModel(entity);

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            throw new AlgorithmNotFoundException(algorithmNotFoundException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , algorithmNotFoundException);
        } catch (final EntityAlreadyExistsException entityAlreadyExistsException) {
            throw new EntityAlreadyExistsException(entityAlreadyExistsException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , entityAlreadyExistsException);
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            throw new EntityCategoryNotFoundException(entityCategoryNotFoundException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , entityCategoryNotFoundException);
        } catch (final EntityServiceException entityServiceException) {
            throw new EntityServiceException(entityServiceException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , entityServiceException);
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            throw new InvalidEntityAttributeException(invalidEntityAttributeException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , invalidEntityAttributeException);
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            throw new InvalidEntityCategoryException(invalidEntityCategoryException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , invalidEntityCategoryException);
        } catch (final InvalidProfileException invalidProfileException) {
            throw new InvalidProfileException(invalidProfileException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , invalidProfileException);
        } catch (final InvalidSubjectAltNameExtension inValidSubjectAltNameExtension) {
            throw new InvalidSubjectAltNameExtension(inValidSubjectAltNameExtension.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , inValidSubjectAltNameExtension);
        } catch (final InvalidSubjectException inValidSubjectException) {
            throw new EntityServiceException(inValidSubjectException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , inValidSubjectException);
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            throw new MissingMandatoryFieldException(missingMandatoryFieldException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , missingMandatoryFieldException);
        } catch (final ProfileNotFoundException profileNotFoundException) {
            throw new ProfileNotFoundException(profileNotFoundException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , profileNotFoundException);
        } catch (final UnsupportedCRLVersionException unSupportedCRLVersionException) {
            throw new UnsupportedCRLVersionException(unSupportedCRLVersionException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , unSupportedCRLVersionException);
        } catch (final CRLExtensionException crlExtensionException) {
            throw new CRLExtensionException(crlExtensionException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , crlExtensionException);
        } catch (final InvalidCRLGenerationInfoException invalidCRLGenerationInfoException) {
            throw new InvalidCRLGenerationInfoException(invalidCRLGenerationInfoException.getMessage() + FOR_ENTITY + getEntityName(entity, entityType) , invalidCRLGenerationInfoException);
        }
    }

    private <T extends AbstractEntity> void setIdToEntities(final List<T> validEntities, final Map<String, Long> entityIdDetails) {

        for (final T validEntity : validEntities) {
            if (validEntity.getType() == EntityType.ENTITY) {
                final Entity entity = (Entity) validEntity;
                entity.getEntityInfo().setId(entityIdDetails.get(entity.getEntityInfo().getName()));
                logger.debug("Entity id is::{}", entity.getEntityInfo().getId());
            } else {
                final CAEntity caEntity = (CAEntity) validEntity;
                caEntity.getCertificateAuthority().setId(entityIdDetails.get(caEntity.getCertificateAuthority().getName()));
                logger.debug("CAEntity id is::{}", caEntity.getCertificateAuthority().getId());
            }
        }
    }

    private List<AbstractEntity> getEntitiesList(final Entities entities) {

        final List<AbstractEntity> abstractEntities = new ArrayList<AbstractEntity>();
        if (entities.getCAEntities() != null) {
            abstractEntities.addAll(entities.getCAEntities());
        }
        if (entities.getEntities() != null) {
            abstractEntities.addAll(entities.getEntities());
        }
        return abstractEntities;
    }

    private <E extends AbstractEntityData> void persistManagerEntities(final List<E> entityModels, final Map<String, Long> entititesIDMap) throws AlgorithmNotFoundException,
            EntityAlreadyExistsException, EntityServiceException, InvalidEntityException {

        EntityType entityType = null;
        for (final E entityData : entityModels) {

            try {
                if (entityData instanceof EntityData) {
                    entityType = EntityType.ENTITY;
                    final EntityData entityDataFromDB = (EntityData) entitiesManager.persistEntityData(entityData, entityType);

                    final EntityPersistenceHandler<Entity> entityPersistenceHandler = (EntityPersistenceHandler<Entity>) entitiesManager.getEntitiesPersistenceHandler(EntityType.ENTITY);
                    entityPersistenceHandler.persistSubjectIdentificationData(entityDataFromDB);
                    storeEntityID(entityDataFromDB, entityType, entititesIDMap);

                } else {
                    entityType = EntityType.CA_ENTITY;
                    final CAEntityData entityDataFromDB = (CAEntityData) entitiesManager.persistEntityData(entityData, entityType);
                    storeEntityID(entityDataFromDB, entityType, entititesIDMap);
                }
            } catch (final EntityServiceException entityServiceException) {
                throw new EntityServiceException(entityServiceException.getMessage() + FOR_ENTITY + getEntityName(entityData, entityType) , entityServiceException);
            } catch (final EntityAlreadyExistsException entityEntityAlreadyExistsException) {
                throw new EntityAlreadyExistsException(entityEntityAlreadyExistsException.getMessage() + FOR_ENTITY + getEntityName(entityData, entityType) , entityEntityAlreadyExistsException);
            }

        }
    }

    private <E extends AbstractEntityData> void storeEntityID(final E entityDataFromDB, final EntityType entityType, final Map<String, Long> entitiesIDMap) {

        switch (entityType) {
        case ENTITY:
            final EntityData entityData = (EntityData) entityDataFromDB;
            entitiesIDMap.put(entityData.getEntityInfoData().getName(), entityData.getId());
            return;

        case CA_ENTITY:
            final CAEntityData caEntityData = (CAEntityData) entityDataFromDB;
            entitiesIDMap.put(caEntityData.getCertificateAuthorityData().getName(), caEntityData.getId());
            return;

        default:
            throw new ValidationException("Undefined Entity Type");
        }
    }

    private String getEntityName(final AbstractEntityData entity, final EntityType entityType) {

        String entityDataName = null;
        switch (entityType) {
        case ENTITY:
            final EntityData entityData = (EntityData) entity;
            entityDataName = entityData.getEntityInfoData().getName();
            break;
        case CA_ENTITY:
            final CAEntityData caEntityData = (CAEntityData) entity;
            entityDataName = caEntityData.getCertificateAuthorityData().getName();
            break;
        default:
            throw new ValidationException("Undefined Entity Type");
        }
        return entityDataName;
    }

    private String getEntityName(final AbstractEntity entity, final EntityType entityType) {
        String entityName = null;
        switch (entityType) {
        case ENTITY:
            final Entity endEntity = (Entity) entity;
            entityName = endEntity.getEntityInfo().getName();
            break;
        case CA_ENTITY:
            final CAEntity caEntity = (CAEntity) entity;
            entityName = caEntity.getCertificateAuthority().getName();
            break;
        default:
            throw new ValidationException("Undefined Entity Type");
        }
        return entityName;
    }
}
