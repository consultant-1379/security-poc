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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Table;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.SearchType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntitiesModelMapperFactoryv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.SubjectIdentificationData;

/**
 * This class implements some of the methods in {@link EntitiesPersistenceHandler} And this class holds common methods for DB CRUD Operation.
 *
 * @param <T>
 *            Class extending {@link AbstractEntity} i.e., {@link CAEntity} / {@link Entity}.
 */

public abstract class AbstractEntityPersistenceHandler<T extends AbstractEntity> implements EntitiesPersistenceHandler<T> {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    EntitiesModelMapperFactory entitiesModelMapperFactory;

    @Inject
    EntitiesModelMapperFactoryv1 entitiesModelMapperFactoryv1;

    @Inject
    Logger logger;

    protected static final int SUCCESS = 0;
    protected static final int FAIL = 1;
    protected static final String ENTITY_ID = "entityId";

    /**
     * This method calls the {@link EntitiesModelMapperFactory} and get the appropriate instance of {@link ModelMapper}
     *
     * @return Instance of {@link ModelMapper}
     *
     * @throws InvalidEntityException
     *             thrown when invalid entity type is passed.
     */
    protected ModelMapper getEntitiesMapper(final EntityType entityType) throws InvalidEntityException {
        final ModelMapper entitiesMapper = entitiesModelMapperFactory.getEntitiesMapper(entityType);
        return entitiesMapper;
    }


    /**
     * This method calls the {@link EntitiesModelMapperFactory} and get the appropriate instance of {@link ModelMapper}
     * @return Instance of {@link ModelMapper}
     * @throws InvalidEntityException
     *             thrown when invalid entity type is passed.
     */
    protected ModelMapperv1 getEntitiesMapperv1(final EntityType entityType) throws InvalidEntityException {
        return entitiesModelMapperFactoryv1.getEntitiesMapper(entityType);
    }

    /**
     * This method is used for create operation.
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} that is to be persisted.
     *
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when EntityType other than CAEntity/Entity is passed
     */
    public <E extends AbstractEntityData> E persistEntity(final T entity) throws EntityAlreadyExistsException, EntityServiceException, InvalidEntityException {
        final String entityType = entity.getType().toString();
        try {
            final E entityData = getEntitiesMapper(entity.getType()).fromAPIToModel(entity);
            persistenceManager.createEntity(entityData);

            logger.debug("{} Created {}", entityType, entity);
            return entityData;
        } catch (final javax.persistence.EntityExistsException entityExistsException) {
            logger.error("Entity Already Exists {}", entityExistsException.getMessage());
            throw new EntityAlreadyExistsException(ProfileServiceErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (final javax.persistence.TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entity {}", transactionRequiredException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final PersistenceException exception) {
            logger.error("Error in creating {}. {}", entityType, exception.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_CREATING + entityType + exception.getMessage(), exception);
        }
    }

    /**
     * This method is used to persist Entity/CAEntity
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} that is to be persisted.
     * @return entity {@link CAEntityData}/ {@link EntityData} that is to be persisted.
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public <T extends AbstractEntityData> T persistEntityData(final T entityData) throws EntityAlreadyExistsException, EntityServiceException {

        try {
            persistenceManager.createEntity(entityData);
            return entityData;

        } catch (final javax.persistence.EntityExistsException entityExistsException) {
            logger.error("Entity Already Exists {}", entityExistsException.getMessage());
            throw new EntityAlreadyExistsException(ProfileServiceErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (final javax.persistence.TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entity {}", transactionRequiredException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final PersistenceException exception) {
            logger.error("Error in creating enity {}", exception.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_CREATING, exception);
        }
    }

    /**
     * This method is used for update operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Update in DB.</li>
     * <li>Retrieve updated Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} that is to be updated.
     *
     * @return {@link CAEntity}/ {@link Entity} that is updated successfully.
     *
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given input.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid Attribute.
     */
    @Override
    public <E extends AbstractEntityData> T updateEntity(T entity) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        final String entityType = entity.getType().toString();

        try {
            final E entityData = getEntitiesMapper(entity.getType()).fromAPIToModel(entity);

            final E mergedEntityData = findAndMergeEntityData(entityData);
            final E updatedEntityData = persistenceManager.updateEntity(mergedEntityData);

            updateSubjectIdentificationData(updatedEntityData);

            if (entityType.equals("CA_ENTITY")) {
                entity = getEntitiesMapperv1(entity.getType()).toApi(updatedEntityData, MappingDepth.LEVEL_0);
            } else {
                entity = getEntitiesMapperv1(entity.getType()).toApi(updatedEntityData, MappingDepth.LEVEL_1);
            }
        } catch (final javax.persistence.TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating Entity {}", transactionRequiredException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error occured in updating {}. {}", entityType, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_UPDATING + entityType, persistenceException);
        }

        logger.debug("{} Updated {}", entityType, entity);

        return entity;
    }

    /**
     * This method finds the given entity data in DB and merges with it
     *
     * @param entityData
     *            entity data that has to be found and merged
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given input.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public abstract <E extends AbstractEntityData> E findAndMergeEntityData(E entityData) throws EntityNotFoundException, EntityServiceException;

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    public <E extends AbstractEntityData> List<T> getEntities(final Class<E> entityClass, final EntityType entityType) throws EntityServiceException, InvalidEntityException,
    InvalidEntityAttributeException, InvalidProfileAttributeException {

        List<T> entities = new ArrayList<T>();

        try {
            final List<E> entitiesData = (List<E>) persistenceManager.getAllEntityItems(entityClass);

            entities = getEntitiesMapperv1(entityType).toApi(entitiesData, MappingDepth.LEVEL_1);

        } catch (final PersistenceException persistenceException) {
            logger.error("Error occured in retrieving {}. {}", entityType, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, persistenceException);
        }

        logger.debug("Entities Retrieved {}", entities);
        return entities;
    }

    /**
     * This method is used for retrieving entities in bulk used for import Entity operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    public <E extends AbstractEntityData> List<T> getEntitiesforImport(final Class<E> entityClass, final EntityType entityType)
            throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {

        final List<T> entities = new ArrayList<T>();

        try {
            final List<E> entitiesData = (List<E>) persistenceManager.getAllEntityItems(entityClass);

            for (final E dataModel : entitiesData) {
                try {
                    final T entity = entitiesModelMapperFactoryv1.getEntitiesExportMapper(entityType).toAPIFromModel(dataModel);
                    if (entity != null) {
                        entities.add(entity);
                    }
                } catch (final CAEntityNotInternalException ex) {
                    logger.debug("Found external CA", ex);
                }
            }

        } catch (final PersistenceException persistenceException) {
            logger.error("Error occured in retrieving {}. {}", entityType, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, persistenceException);
        }

        logger.debug("Entities Retrieved {}", entities);

        return entities;
    }

    /**
     * This method is used for retrieve operation by ID/Name or both. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param id
     *            id of entity to be retrieved.
     *
     * @param name
     *            name of entity to be retrieved.
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @param namePath
     *            Path of Field name in JPA Entity separated by '.'
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             Thrown when name or id passed are invalid.
     */
    protected <E extends AbstractEntityData> E getEntityData(final long id, final String name, final Class<E> entityDataClass, final String namePath) throws EntityNotFoundException,
            EntityServiceException, InvalidEntityAttributeException {
        E entityData;
        final SearchType searchType = getSearchType(id, name);
        switch (searchType) {
        case ID:
            entityData = getEntityById(id, entityDataClass);
            break;
        case NAME:
            entityData = getEntityByName(name.trim(), entityDataClass, namePath);
            break;
        case BOTH:
            entityData = getEntityByNameAndId(id, name.trim(), entityDataClass, namePath);
            break;
        default:
            throw new InvalidEntityAttributeException("Invalid Id or Name for " + entityDataClass.getAnnotation(Table.class).name());
        }

        return entityData;
    }

    /**
     * get the {@link SearchType} whether the profile needs to be retrieved based on id or name.
     *
     * @param id
     *            id, using which JPA Entity to be retrieved
     * @param name
     *            name, using which JPA Entity to be retrieved
     * @return {@link SearchType}
     *
     * @throws InvalidEntityAttributeException
     *             Thrown when name or id passed are invalid.
     */
    public SearchType getSearchType(final long id, final String name) throws InvalidEntityAttributeException {
        if (id == 0 && name == null) {
            logger.error(ProfileServiceErrorCodes.ID_OR_NAME_SHOULD_PRESENT);
            throw new InvalidEntityAttributeException(ProfileServiceErrorCodes.ID_OR_NAME_SHOULD_PRESENT);
        }

        if (id != 0 && name != null) {
            return SearchType.BOTH;
        }
        if (id != 0) {
            return SearchType.ID;
        } else {
            return SearchType.NAME;
        }
    }

    /**
     * This method is used for retrieve operation by Id. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param id
     *            id of entity to be retrieved.
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID.
     */
    @Override
    public <E> E getEntityById(final long id, final Class<E> entityClass) throws EntityServiceException, EntityNotFoundException {

        E entityData = null;
        final String entityType = entityClass.getAnnotation(Table.class).name();
        try {
            entityData = (E) persistenceManager.findEntity(entityClass, id);
        } catch (final PersistenceException e) {
            logger.error("Error in retrieving {}. {}", entityType, e.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, e);
        }

        if (entityData == null) {
            throw new EntityNotFoundException(entityType + ProfileServiceErrorCodes.NOT_FOUND_WITH_ID + id);
        }
        return entityData;
    }

    /**
     * This method is used for retrieve operation by Name. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param name
     *            name of entity to be retrieved.
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @param namePath
     *            Path of Field name in JPA Entity separated by '.'
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     */
    @Override
    public <E> E getEntityByName(final String name, final Class<E> entityClass, final String namePath) throws EntityServiceException, EntityNotFoundException {

        E entityData = null;
        final String entityType = entityClass.getAnnotation(Table.class).name();
        try {
            entityData = persistenceManager.findEntityByName(entityClass, name, namePath);
        } catch (final PersistenceException e) {
            logger.error("Error in retrieving {}. {}", entityType, e.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, e);
        }

        if (entityData == null) {
            throw new EntityNotFoundException(entityType + ProfileServiceErrorCodes.NOT_FOUND_WITH_NAME + name);
        }
        return entityData;
    }

    /**
     * This method is used check the availability of Name used for {@link CAEntity}/ {@link Entity}
     *
     * @param name
     *            name of entity to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     *
     */
    protected <E> boolean isNameAvailable(final String name, final Class<E> entityClass, final String namePath) throws EntityServiceException {

        E entityData = null;
        final String entityType = entityClass.getAnnotation(Table.class).name();
        try {
            entityData = persistenceManager.findEntityByName(entityClass, name, namePath);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error occured in retrieving {}. {}", entityType, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, persistenceException);
        }

        if (entityData == null) {
            return true;
        }
        return false;
    }

    /**
     * This method is used for retrieve operation by ID and Name. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param name
     *            name of entity to be retrieved.
     *
     * @param id
     *            id of entity to be retrieved.
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @param namePath
     *            Path of Field name in JPA Entity separated by '.'
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public <E extends AbstractEntityData> E getEntityByNameAndId(final long id, final String name, final Class<E> entityClass, final String namePath) throws EntityNotFoundException,
            EntityServiceException {
        E entityData = null;
        final String entityType = entityClass.getAnnotation(Table.class).name();
        try {
            entityData = persistenceManager.findEntityByIdAndName(entityClass, id, name, namePath);
        } catch (final PersistenceException e) {
            logger.error("Error in retrieving {}. {}", entityType, e.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, e);
        }

        if (entityData == null) {
            throw new EntityNotFoundException(entityType + ProfileServiceErrorCodes.NOT_FOUND_WITH_ID_AND_NAME + id + " " + name);
        }
        return entityData;
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @param input
     *            {@link java.util.Map} containing attribute and its value that are to be used in WHERE condition in query.
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public <E> E getEntityWhere(final Class<E> entityClass, final Map<String, Object> inputs) throws EntityServiceException {

        E entityData = null;
        final String entityType = entityClass.getAnnotation(Table.class).name();
        try {
            entityData = persistenceManager.findEntityWhere(entityClass, inputs);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving {}. {}", entityType, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entityType, persistenceException);
        }

        return entityData;
    }

    /**
     * This method is used to update the subject Identification data when a corresponding entity is modified
     *
     * @param updatedEntityData
     *            Entity data from which subject_dn is hashed.
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws PersistenceException
     *             Thrown by the persistence provider when a problem occurs
     */
    public <E extends AbstractEntityData> void updateSubjectIdentificationData(final E updatedEntityData) throws AlgorithmNotFoundException, PersistenceException {
        if (updatedEntityData instanceof EntityData) {

            final EntityData entityData = (EntityData) updatedEntityData;
            final byte[] subjectDNhash = SubjectUtils.generateSubjectDNHash(entityData.getEntityInfoData().getSubjectDN());
            final SubjectIdentificationData subjectDNHashData = getSubjectIdentificationData(entityData.getId());
            if (subjectDNHashData != null) {
                subjectDNHashData.setSubjectDNHash(subjectDNhash);
                persistenceManager.updateEntity(subjectDNHashData);
            } else {
                final SubjectIdentificationData subjectDNHashDataToPersist = new SubjectIdentificationData();
                subjectDNHashDataToPersist.setEntityId(entityData.getId());
                subjectDNHashDataToPersist.setSubjectDNHash(subjectDNhash);
                persistenceManager.createEntity(subjectDNHashDataToPersist);
            }

        }
    }

    protected SubjectIdentificationData getSubjectIdentificationData(final long entityId) throws PersistenceException {
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_ID, entityId);
        final SubjectIdentificationData subjectDNHashData = persistenceManager.findEntityWhere(SubjectIdentificationData.class, input);
        return subjectDNHashData;
    }

    protected List<SubjectIdentificationData> getSubjectIdentificationDatas(final byte[] hash) throws PersistenceException {

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("subjectDNHash", hash);
        final List<SubjectIdentificationData> entitySubjectDatas = (List<SubjectIdentificationData>) persistenceManager.findEntitiesWhere(SubjectIdentificationData.class, attributes);
        if (ValidationUtils.isNullOrEmpty(entitySubjectDatas)) {
            return null;
        }
        return entitySubjectDatas;
    }

    /**
     * This method is used to merge CertificateExpiryNotificationDetails and CertificateExpiryNotificationDetailsData.
     *
     * @param entityData
     *            {@link CAEntityData}/ {@link EntityData} that is to be persisted.
     *
     * @return Set<CertificateExpiryNotificationDetailsData> which contains merged CertificateExpiryNotificationDetailsData for update.
     */
    protected abstract <T extends AbstractEntityData> Set<CertificateExpiryNotificationDetailsData> mergeCertificateExpiryNotificationDetails(final T entityData);
}
