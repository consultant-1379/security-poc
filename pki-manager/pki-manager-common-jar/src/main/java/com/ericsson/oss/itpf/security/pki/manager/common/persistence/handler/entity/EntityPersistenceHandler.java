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

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;
import javax.naming.InvalidNameException;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.EntityStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyDeletedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.SubjectIdentificationData;

/**
 * This class is responsible for {@link Entity} DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model {@link Entity} to JPA Entity {@link EntityData}</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model {@link Entity} if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractEntity} i.e., {@link Entity}.
 */
@EntityQualifier(EntityType.ENTITY)
public class EntityPersistenceHandler<T extends AbstractEntity> extends AbstractEntityPersistenceHandler<T> {
    private static final int NOT_AFTER_TOLERANCE = 4;

    @Inject
    EntityFilterDynamicQueryBuilder entityFilterDynamicQueryBuilder;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntityModelMapper entityModelMapper;

    private final static String NAME_PATH = "entityInfoData.name";
    private final static String ENTITY_CATEGORY_ID = "entityCategoryData";
    private final static String NAME = "name";

    private static final String queryForEntitiesCount = "select count(e.*) from entity e ";
    private static final String UPDATE_ENTITYSTATUS_TOINACTIVE_NATIVEQUERY =
            "update entity SET status_id=3 where id not in (select distinct e_cert.entity_id from entity_certificate e_cert where e_cert.certificate_id in (select cert.id from certificate cert where cert.status_id in (1,4))) and status_id = 2";
    private static final String GET_CERTIFICATE_EXPIRY_NOTIFICATION_DETAILS_QUERY =
            "select c from CertificateExpiryNotificationDetailsData c where c.id in(select cendd.id from EntityData ed inner join ed.certificateExpiryNotificationDetailsData cendd  WHERE ed.entityInfoData.name = :name and cendd.notificationSeverity= :severity) ORDER BY c.id DESC";
    private final static int maxExpectedEntitySubjectDatas = 2;

    /**
     * This method is used for create operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Persist into DB.</li>
     * <li>Retrieve created Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link Entity} that is to be persisted.
     * @return {@link Entity} that is persisted successfully.
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when invalid entity type is passed.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity has invalid attribute.
     */
    @Override
    public T createEntity(final T entity)
            throws AlgorithmNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        final Entity inputEntity = (Entity) entity;
        final String name = inputEntity.getEntityInfo().getName();

        persistEntity(entity);

        final EntityData enData = getEntityByName(name, EntityData.class, NAME_PATH);

        persistSubjectIdentificationData(enData);

        return getEntitiesMapperv1(entity.getType()).toApi(enData, MappingDepth.LEVEL_1);
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link Entity} with Id/name Set.
     * @return {@link Entity} that is retrieved successfully.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when invalid entity type is passed.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity has invalid attribute.
     */
    @Override
    public T getEntity(final T entity)
            throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        final Entity inputEntity = (Entity) entity;
        final EntityData entityData = getEntitydata(inputEntity);
        return getEntitiesMapperv1(entity.getType()).toApi(entityData, MappingDepth.LEVEL_1);
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model without the certificates of that entity.</li>
     * </ul>
     *
     * @param entity
     *            {@link Entity} with Id/name Set.
     * @return {@link Entity} that is retrieved successfully.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     */
    public T getEntityForCertificateGeneration(final T entity)
            throws EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException, InvalidProfileAttributeException {

        final Entity inputEntity = (Entity) entity;
        final EntityData entityData = getEntitydata(inputEntity);
        return entityModelMapper.toApi(entityData, MappingDepth.LEVEL_1);
    }

    /**
     * @param entity
     *            {@link Entity} that has ID/Name set.
     * @return {@link EntityData} that is retrieved from DB based on given ID/Name.
     * @throws EntityNotFoundException
     *             thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     */
    private EntityData getEntitydata(final Entity entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        final long id = entity.getEntityInfo().getId();
        final String name = entity.getEntityInfo().getName();
        return getEntityData(id, name, EntityData.class, NAME_PATH);
    }

    /**
     * This method is used for delete operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>Delete from DB if is not being used any other JPA Entities.</li>
     * <li>Form the Response Object and return.</li>
     * </ul>
     *
     * @param entity
     *            {@link Entity} that is to be deleted.
     * @return {@link ProfileManagerResponse} with status messages set.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity is invalid.
     */
    @Override
    public void deleteEntity(final T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        final Entity inputEntity = (Entity) entity;
        final String name = inputEntity.getEntityInfo().getName();

        final EntityData entityData = getEntitydata(inputEntity);

        try {
            if (entityData.getEntityInfoData().getStatus() == EntityStatus.NEW) {
                persistenceManager.deleteEntity(entityData);
                deleteSubjectIdentificationData(entityData);
            } else {
                entityData.getEntityInfoData().setStatus(EntityStatus.DELETED);
                persistenceManager.updateEntity(entityData);
            }
        } catch (final javax.persistence.TransactionRequiredException e) {
            logger.error("Error in deleting entity {}. {}", name, e.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "Entity", e);
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("Error in deleting entity {}. {}", name, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "Entity", persistenceException);
        }
    }

    /**
     * This method is used to check the Entity is allowed to be deleted or not based on its Status.
     *
     * @throws EntityAlreadyDeletedException
     *             Thrown when the entity is already in deleted state.
     * @throws EntityInUseException
     *             Thrown when the entity is in Active state.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity is invalid.
     */
    @Override
    public boolean isDeletable(final T entity) throws EntityAlreadyDeletedException, EntityInUseException, EntityNotFoundException,
            EntityServiceException, InvalidEntityAttributeException {
        boolean isDeletable = false;
        final Entity inputEntity = (Entity) entity;
        final EntityData entityData = getEntitydata(inputEntity);

        final EntityStatus entityStatus = entityData.getEntityInfoData().getStatus();

        switch (entityStatus) {
            case NEW:
            case INACTIVE: {
                isDeletable = true;
                break;
            }
            case REISSUE: {
                logger.error("Entity is being Reissued");
                throw new EntityServiceException("Entity is being Reissued. It cannot be deleted");
            }
            case DELETED: {
                logger.error("Entity is already deleted");
                throw new EntityAlreadyDeletedException("Entity is already deleted");
            }
            case ACTIVE: {
                logger.error("Entity has a valid certificate. It cannot be deleted.");
                throw new EntityInUseException("Entity has a valid certificate. It cannot be deleted.");
            }
        }

        return isDeletable;
    }

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return Instance of {@link Entities} containing {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    @Override
    public Entities getEntities(final EntityType entityType)
            throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {
        final Entities entities = new Entities();
        entities.setEntities((List<Entity>) getEntities(EntityData.class, entityType));
        return entities;
    }

    /**
     * This method is used check the availability of Name used for {@link Entity}
     *
     * @param name
     *            name of entity to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public boolean isNameAvailable(final String name) throws EntityServiceException {
        return isNameAvailable(name, EntityData.class, NAME_PATH);
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
     */
    public String getOtp(final Entity entity) throws EntityNotFoundException, EntityServiceException {
        EntityData entityData = null;
        try {
            entityData = getEntityByName(entity.getEntityInfo().getName(), EntityData.class, NAME_PATH);
            int oTPCount = entityData.getEntityInfoData().getOtpCount();

            entityData.getEntityInfoData().setOtpCount(--oTPCount);
            persistenceManager.updateEntity(entityData);

        } catch (final EntityServiceException e) {
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "Entity", e);
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + persistenceException.getMessage());
            throw new EntityServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, persistenceException);
        }
        return entityData.getEntityInfoData().getOtp();
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entityCategory
     *            {@link EntityCategory} with Id/name Set.
     * @param isIssuerDataRequired
     *            If false, then the issuer certificates data is not retrieved.
     * @return List of {@link Entity} that is retrieved successfully.
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category is not found in the system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity Type is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             Thrown when Invalid Attribute is found while mapping Entity.
     */
    @Override
    public List<T> getEntitiesByCategory(final EntityCategory entityCategory, final Boolean isIssuerDataRequired)
            throws EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        final List<EntityData> entityDatas = getEntitiesDataByCategory(entityCategory);
        final ModelMapperv1 modelMapper = getEntitiesMapperv1(EntityType.ENTITY);
        logger.info("getEntitiesByCategory: Mapping model to the api issuer data required: {}", isIssuerDataRequired);
        List<Entity> entitiesList = null;
        if (isIssuerDataRequired) {
            entitiesList = modelMapper.toApi(entityDatas, MappingDepth.LEVEL_1);
        } else {
            entitiesList = modelMapper.toApiWithoutIssuerData(entityDatas);
        }
        logger.info("getEntitiesByCategory: size of entitiesList {}", entitiesList.size());
        return (List<T>) entitiesList;
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entityCategory
     *            {@link EntityCategory} with Id/name Set.
     * @return List of {@link Entity} that is retrieved successfully.
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category is not found in the system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity Type is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             Thrown when Invalid Attribute is found while mapping Entity.
     */
    @Override
    public List<T> getEntitiesSummaryByCategory(final EntityCategory entityCategory)
            throws EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {

        final List<EntityData> entityDatas = getEntitiesDataByCategory(entityCategory);
        logger.info("getEntitiesSummaryByCategory: Mapping model to the api [{}] and id [{}]", entityCategory.getName(), entityCategory.getId());
        final List<Entity> entitiesList = entityModelMapper.toApi(entityDatas, MappingDepth.LEVEL_0);
        logger.info("getEntitiesSummaryByCategory: size of entitiesList {}", entitiesList.size());
        return (List<T>) entitiesList;
    }

    /**
     * @param entityCategory
     * @param entityDatas
     * @return
     */
    private List<EntityData> getEntitiesDataByCategory(final EntityCategory entityCategory) {
        List<EntityData> entityDatas = null;
        try {

            final EntityCategoryData entityCategoryData =
                    persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME);
            final Map<String, Object> input = new HashMap<String, Object>();
            input.put(ENTITY_CATEGORY_ID, entityCategoryData);

            logger.debug("Fetching entities by category from the database");
            entityDatas = persistenceManager.findEntitiesWhere(EntityData.class, input);
            if (entityDatas == null) {
                throw new EntityNotFoundException(ProfileServiceErrorCodes.NO_ENTITIES_FOUND_WITH_CATEGORY + entityCategory.getName());
            }
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while getting linked entities. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITIES, persistenceException);
        }
        return entityDatas;
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances without active certificate or certificate expired at the given date.</li>
     * <li>Map such JPA Entities to API models.</li>
     * <li>Return those API models.</li>
     * </ul>
     *
     * @param notAfter
     *            The date to check the certificate validity
     * @param maxEntities
     *            The maximum number of Entities retrieved. Set to a negative value to retrieve all the filtered Entities.
     * @param entityCategories
     *            EntityCategory list
     * @return Returns list of entities based on the value sent in entityCategories object at the notAfter date.
     * @throws EntityCategoryNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws MissingMandatoryFieldException
     *             Thrown when the notAfter date is null
     */
    @SuppressWarnings("unchecked")
    public List<T> getEntitiesWithInvalidCertificate(final Date notAfter, final int maxEntities, final EntityCategory... entityCategories)
            throws EntityCategoryNotFoundException,
            EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, MissingMandatoryFieldException {

        if (notAfter == null) {
            throw new MissingMandatoryFieldException("notAfter date is null");
        }

        final List<Entity> entityDataToReturn = new ArrayList<>();
        // Retrieve active entity with active certificate are going to expire
        final List<Entity> entityDatas = getEntitiesByCategoryAndCertificateValidity(notAfter, entityCategories);
        entityDataToReturn.addAll(entityDatas);
        // Retrieve active entity without active certificate
        final List<Entity> entityDatasWithoutActiveCertificate = getEntitiesByCategoryAndNotActiveCertificate(entityCategories);
        entityDataToReturn.addAll(entityDatasWithoutActiveCertificate);

        if (maxEntities < 0 || entityDataToReturn.size() <= maxEntities) {
            return (List<T>) entityDataToReturn;
        }
        Collections.shuffle(entityDataToReturn);
        return (List<T>) new ArrayList<>(entityDataToReturn.subList(0, maxEntities));
    }

    /**
     * This method use to fetch Entity with associated Issuer and SerialNumber
     *
     * @param issuerName
     *            Name of the issuer
     * @param serialNumber
     *            Serial number of the signed Certificate
     * @throws SerialNumberNotFoundException
     *             thrown when the request serialnumber not found or not signed by the provided issuer
     * @return Entityname
     */
    public String getEntityNameByCaNameAndSerialNumber(final String issuerName, final String serialNumber) throws SerialNumberNotFoundException {
        final List<EntityData> entities = getEntityListByCANameAndSerialNumber(issuerName, serialNumber);
        for (final EntityData entity : entities) {
            final Set<CertificateData> certificates = entity.getEntityInfoData().getCertificateDatas();
            for (final CertificateData certificate : certificates) {
                if (certificate.getSerialNumber().equals(serialNumber)) {
                    if (CertificateStatus.ACTIVE.getId() == certificate.getStatus().intValue()) {
                        return entity.getEntityInfoData().getName();
                    }
                    throw new SerialNumberNotFoundException("serialNumber {} not active " + serialNumber);
                }
            }
        }
        throw new SerialNumberNotFoundException("serialNumber {} not found " + serialNumber);
    }

    /**
     * Method for Getting list of Entities issued by a CA
     *
     * @param issuerName
     * @return List of EntityData.
     * @throws SerialNumberNotFoundException
     */
    public List<EntityData> getEntityListByCANameAndSerialNumber(final String issuerName, final String serialNumber)
            throws SerialNumberNotFoundException {
        List<EntityData> entities = null;
        final javax.persistence.Query query = persistenceManager.getEntityManager().createQuery(
                "select e from EntityData e inner join e.entityInfoData.certificateDatas as cdata "
                        + " where e.entityProfileData.certificateProfileData in "
                        + "(select cp from CertificateProfileData cp where cp.issuerData.certificateAuthorityData.name = :caName )"
                        + "  and cdata.serialNumber = :serialNumber ");

        query.setParameter("caName", issuerName);
        query.setParameter("serialNumber", serialNumber);
        entities = query.getResultList();

        if (entities.isEmpty()) {
            throw new SerialNumberNotFoundException("combination of caName {} and SerialNumber {} not found" + issuerName + ", " + serialNumber);
        }
        return entities;
    }

    /**
     * This method use to fetch EntityName with associated Issuer
     *
     * @param issuerName
     *            Name of the issuer
     * @throws CANotFoundException
     *             thrown when the provided issued not found or does not exist
     * @return List of Entityname
     */
    public List<String> getEntityNameListByCaName(final String issuerName) throws CANotFoundException {
        final List<String> entitiesName = new ArrayList<>();

        final List<EntityData> entities = getEntityListByCaName(issuerName);
        for (final EntityData entity : entities) {
            entitiesName.add(entity.getEntityInfoData().getName());

            final Set<CertificateData> d = entity.getEntityInfoData().getCertificateDatas();
            for (final Iterator iterator = d.iterator(); iterator.hasNext();) {
                final CertificateData certificateData = (CertificateData) iterator.next();
                logger.info(entity.getEntityInfoData().getName() + "  " + certificateData.getSerialNumber());
            }
        }
        return entitiesName;
    }

    /**
     * This method use to fetch EntityData with associated Issuer
     *
     * @param issuerName
     *            Name of the issuer
     * @throws CANotFoundException
     *             thrown when the provided issued not found or does not exist
     * @return List of Entityname
     */
    private List<EntityData> getEntityListByCaName(final String issuerName) throws CANotFoundException {
        List<EntityData> entities = null;
        final javax.persistence.Query query = persistenceManager.getEntityManager().createQuery(
                "select e from EntityData e  " + " where e.entityProfileData.certificateProfileData in "
                        + "(select cp from CertificateProfileData cp where cp.issuerData.certificateAuthorityData.name = :caName )");

        query.setParameter("caName", issuerName);
        entities = query.getResultList();

        if (entities.isEmpty()) {
            throw new CANotFoundException("caName {} not found" + issuerName);
        }
        return entities;
    }

    /**
     * Fetch the EntityName list from associated trustProfileName
     *
     * @param trustProfileName
     *            TrustProfile Name
     * @return List of EntityName(s) List of Entity names
     * @throws ProfileNotFoundException
     *             thrown when the provided profile does not exist
     */
    public List<String> getEntityNameListByTrustProfile(final String trustProfileName) throws ProfileNotFoundException {
        final List<String> entitiesName = new ArrayList<>();
        List<EntityData> entities = null;
        final javax.persistence.Query query = persistenceManager.getEntityManager().createQuery(
                "select e from EntityData e " + "inner join e.entityProfileData.trustProfileDatas tp " + " where tp.name = :trustProfileName ");

        query.setParameter("trustProfileName", trustProfileName);
        entities = query.getResultList();

        if (entities.isEmpty()) {
            throw new ProfileNotFoundException("trustProfileName {} not found" + trustProfileName);
        }
        for (final EntityData entity : entities) {
            entitiesName.add(entity.getEntityInfoData().getName());
        }
        return entitiesName;
    }

    /**
     * This methods actually sets OTP on the entityInfo and updates in DB
     *
     * @param entity
     * @throws EntityNotFoundException
     *             when entity is not present in PKI-system
     * @throws EntityServiceException
     *             when there is any error while retrieving info from the entity or fetching entity from data.
     */
    public void setOtp(final Entity entity) throws EntityNotFoundException, EntityServiceException {
        EntityData entityData = null;
        try {
            entityData = getEntityByName(entity.getEntityInfo().getName(), EntityData.class, NAME_PATH);

            entityData.getEntityInfoData().setOtp(entity.getEntityInfo().getOTP());
            entityData.getEntityInfoData().setOtpCount(entity.getEntityInfo().getOTPCount());
            persistenceManager.updateEntity(entityData);
        } catch (final EntityServiceException entityServiceException) {
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "Entity", entityServiceException);
        } catch (final javax.persistence.PersistenceException persistenceException) {
            throw new EntityServiceException("Error occured while updating Entity", persistenceException);
        }
    }

    /**
     * This method finds the given entity data in DB and merges with it
     *
     * @param entityData
     *            entity data that has to be found and merged
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given EntityID.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public <E extends AbstractEntityData> E findAndMergeEntityData(final E entityData) throws EntityNotFoundException, EntityServiceException {
        final EntityData sourceEntityData = (EntityData) entityData;
        final EntityData targetEntityData = getEntityById(sourceEntityData.getId(), EntityData.class);

        final EntityData mergedEntityData = mergeEntityData(sourceEntityData, targetEntityData);

        return (E) mergedEntityData;
    }

    private EntityData mergeEntityData(final EntityData sourceEntityData, final EntityData targetEntityData) {
        final EntityInfoData sourceEntityInfoData = sourceEntityData.getEntityInfoData();
        final EntityInfoData targetEntityInfoData = targetEntityData.getEntityInfoData();

        targetEntityInfoData.setIssuer(sourceEntityInfoData.getIssuer());
        targetEntityInfoData.setName(sourceEntityInfoData.getName());
        targetEntityInfoData.setOtpCount(sourceEntityInfoData.getOtpCount());
        if (sourceEntityInfoData.getStatus() == EntityStatus.REISSUE) {
            if (targetEntityInfoData.getStatus() == EntityStatus.ACTIVE || targetEntityInfoData.getStatus() == EntityStatus.INACTIVE) {
                targetEntityInfoData.setStatus(sourceEntityInfoData.getStatus());
            }
        }
        targetEntityInfoData.setSubjectAltName(sourceEntityInfoData.getSubjectAltName());
        targetEntityInfoData.setSubjectDN(sourceEntityInfoData.getSubjectDN());

        targetEntityData.setOtpValidityPeriod(sourceEntityData.getOtpValidityPeriod());
        targetEntityData.setEntityCategoryData(sourceEntityData.getEntityCategoryData());
        targetEntityData.setEntityInfoData(targetEntityInfoData);
        targetEntityData.setEntityProfileData(sourceEntityData.getEntityProfileData());
        targetEntityData.setKeyGenerationAlgorithm(sourceEntityData.getKeyGenerationAlgorithm());
        targetEntityData.setPublishCertificatetoTDPS(sourceEntityData.isPublishCertificatetoTDPS());
        targetEntityData.setNameAlias(sourceEntityInfoData.getName().toLowerCase());

        if (!ValidationUtils.isNullOrEmpty(sourceEntityData.getCertificateExpiryNotificationDetailsData())) {
            final Set<CertificateExpiryNotificationDetailsData> updateCertExpiryNotificationDetails =
                    mergeCertificateExpiryNotificationDetails(sourceEntityData);
            targetEntityData.getCertificateExpiryNotificationDetailsData().clear();
            targetEntityData.getCertificateExpiryNotificationDetailsData().addAll(updateCertExpiryNotificationDetails);
        }
        targetEntityData.setSubjectUniqueIdentifierValue(sourceEntityData.getSubjectUniqueIdentifierValue());
        setOtpAndOtpGeneratedTime(sourceEntityData.getEntityInfoData().getOtp(), targetEntityData);
        return targetEntityData;
    }

    private void setOtpAndOtpGeneratedTime(final String sourceOTP, final EntityData targetEntityData) {
        if (sourceOTP != null && !sourceOTP.equals(targetEntityData.getEntityInfoData().getOtp())) {
            targetEntityData.getEntityInfoData().setOtp(sourceOTP);
            targetEntityData.setOtpGeneratedTime(new Date());
        }
    }

    /**
     * This method returns count of Entities, applying filter criteria, if any specified.
     *
     * @param entitiesFilter
     *            specifies criteria based on which entities have to be filtered
     * @return count of entities
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public int getEntitiesCountByFilter(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        int count = 0;
        Map<String, Object> attributes = new HashMap<String, Object>();
        final StringBuilder queryforEntitiesCount = new StringBuilder(queryForEntitiesCount);
        try {
            attributes = entityFilterDynamicQueryBuilder.buildWhereQueryForEE(entitiesFilter, queryforEntitiesCount, attributes);
            logger.info("Query in getEntitiesCountWithFilter: {}", queryforEntitiesCount);

            count = ((BigInteger) persistenceManager.findEntityCountByNativeQuery(queryforEntitiesCount.toString(), attributes)).intValue();
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("Error in retrieving count of Entities that match with given filter criteria. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "Entity.", persistenceException);
        }
        return count;
    }

    @SuppressWarnings("unchecked")
    List<Entity> getEntitiesByCategoryAndCertificateValidity(final Date validity, final EntityCategory... entityCategories)
            throws EntityCategoryNotFoundException, EntityServiceException,
            InvalidEntityException, InvalidEntityAttributeException {
        List<EntityData> entityDatas = null;
        final List<Long> entityCategoryIds = new ArrayList<Long>();
        try {
            for (final EntityCategory entityCategory : entityCategories) {
                final EntityCategoryData entityCategoryData =
                        persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME);
                if (entityCategoryData == null) {
                    throw new EntityCategoryNotFoundException();
                } else {
                    entityCategoryIds.add(entityCategoryData.getId());
                }
            }

            final javax.persistence.Query query = persistenceManager.getEntityManager().createQuery(
                    "select e from EntityData e inner join e.entityInfoData.certificateDatas as cdata where e.entityCategoryData.id in(:entityCategories)"
                            + "  and e.entityInfoData.status = :entityStatusInteger and cdata.notAfter <=  date(:validity) and cdata.status = :activeStatusInInteger");

            query.setParameter("entityCategories", entityCategoryIds);
            query.setParameter("activeStatusInInteger", CertificateStatus.ACTIVE.getId());
            query.setParameter("entityStatusInteger", EntityStatus.ACTIVE.getId());
            final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            final String validityStr = sdf.format(validity);
            query.setParameter("validity", validityStr);
            entityDatas = query.getResultList();
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while getting linked entities. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITIES, persistenceException);
        }

        final Map<Long, Date> caNotAfterCache = new HashMap<>();
        final List<EntityData> entityDatasResult = new ArrayList<>();
        for (final EntityData entityData : entityDatas) {
            final Date caNotAfterForEntity = retrieveCANotAfterDate(caNotAfterCache, entityData);
            final Date entityNotAfterForEntity = retrieveEntityNotAfterDate(entityData);
            if (caNotAfterForEntity != null && entityNotAfterForEntity != null) {
                final long diffInMillies = caNotAfterForEntity.getTime() - entityNotAfterForEntity.getTime();
                final long diff = TimeUnit.HOURS.convert(diffInMillies, TimeUnit.MILLISECONDS);
                if (diff >= NOT_AFTER_TOLERANCE) {
                    entityDatasResult.add(entityData);
                }
            } else if (caNotAfterForEntity == null) {
                logger.error("Can't retrieve CA not_after_date for entity id {}", entityData.getId());
            } else if (entityNotAfterForEntity == null) {
                logger.error("Can't retrieve entity not_after_date for entity id {}", entityData.getId());
            }

        }

        List<Entity> entitiesList = new ArrayList<>();
        if (entityDatasResult != null) {
            final ModelMapper modelMapper = getEntitiesMapper(EntityType.ENTITY);
            logger.info("Result for query getEntitiesByCategoryAndCertificateValidity : retrived entities {}", entityDatasResult.size());
            entitiesList = modelMapper.toAPIModelList(entityDatasResult);
        }
        return entitiesList;
    }

    private Date retrieveEntityNotAfterDate(final EntityData entityData) {
        for (final CertificateData certificateData : entityData.getEntityInfoData().getCertificateDatas()) {
            if (certificateData.getStatus() == CertificateStatus.ACTIVE.getId()) {
                return certificateData.getNotAfter();
            }
        }
        return null;
    }

    private Date retrieveCANotAfterDate(final Map<Long, Date> caNotAfterCache, final EntityData entityData) {
        final Long entityProfileId = entityData.getEntityProfileData().getId();
        Date caNotAfterForEntity = null;
        if (caNotAfterCache.containsKey(entityProfileId)) {
            caNotAfterForEntity = caNotAfterCache.get(entityProfileId);
        } else {
            try {
                for (final CertificateData certificateData : entityData.getEntityProfileData().getCertificateProfileData().getIssuerData()
                        .getCertificateAuthorityData().getCertificateDatas()) {
                    if (certificateData.getStatus() == CertificateStatus.ACTIVE.getId()) {
                        caNotAfterForEntity = certificateData.getNotAfter();
                        caNotAfterCache.put(entityProfileId, caNotAfterForEntity);
                        break;
                    }
                }
            } catch (final RuntimeException ex) {
                logger.info("ERROR retrieving date");
            }
        }
        return caNotAfterForEntity;
    }

    @SuppressWarnings("unchecked")
    List<Entity> getEntitiesByCategoryAndNotActiveCertificate(final EntityCategory... entityCategories)
            throws EntityCategoryNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        List<EntityData> entityDatas = null;
        final List<Long> entityCategoryIds = new ArrayList<Long>();
        try {
            for (final EntityCategory entityCategory : entityCategories) {
                final EntityCategoryData entityCategoryData =
                        persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME);
                if (entityCategoryData == null) {
                    throw new EntityCategoryNotFoundException();
                } else {
                    entityCategoryIds.add(entityCategoryData.getId());
                }
            }

            final javax.persistence.Query query = persistenceManager.getEntityManager().createQuery(
                    "select e from EntityData e where e.entityCategoryData.id in (:entityCategories)"
                            + " and e.entityInfoData.status = :entityStatusInteger"
                            + " and e.id not in (select ent.id from EntityData ent inner join ent.entityInfoData.certificateDatas as certificate where certificate.status= :activeStatusInInteger) ");
            query.setParameter("entityCategories", entityCategoryIds);
            query.setParameter("activeStatusInInteger", CertificateStatus.ACTIVE.getId());
            query.setParameter("entityStatusInteger", EntityStatus.ACTIVE.getId());
            entityDatas = query.getResultList();
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while getting linked entities. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITIES, persistenceException);
        }

        List<Entity> entitiesList = new ArrayList<>();

        if (entityDatas != null) {
            final ModelMapper modelMapper = getEntitiesMapper(EntityType.ENTITY);

            logger.info("Mapping model to the api {} Elements", entityDatas.size());

            entitiesList = modelMapper.toAPIModelList(entityDatas);
        }
        return entitiesList;
    }

    /**
     * This method fetches the list of entities based on given entity status value
     *
     * @param entityStatus
     *            the integer value of status of entity
     * @return List of entities which has given entity status
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @Override
    public List<T> getEntitiesByStatus(final int entityStatus)
            throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        List<EntityData> entityDatas = null;
        attributes.put("entityInfoData.status", entityStatus);
        try {
            entityDatas = persistenceManager.findEntitiesWhere(EntityData.class, attributes);
            if (ValidationUtils.isNullOrEmpty(entityDatas)) {
                logger.error("There are no Entities");
                return null;
            }
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("Error in retrieving. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING, persistenceException);
        }
        return getEntitiesMapper(EntityType.ENTITY).toAPIModelList(entityDatas);
    }

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     *
     * @throws EntityStatusUpdateFailedException
     */
    public void updateEntityStatusToInactive() throws EntityStatusUpdateFailedException {
        int updatedEntityCount = 0;
        final javax.persistence.Query query = persistenceManager.getEntityManager().createNativeQuery(UPDATE_ENTITYSTATUS_TOINACTIVE_NATIVEQUERY);
        try {
            updatedEntityCount = query.executeUpdate();

        } catch (javax.persistence.PersistenceException | IllegalStateException e) {
            logger.error("{} while updating Entity status {} {} | {}",
                    ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, e.getMessage(), e.getCause(), e);

            throw new EntityStatusUpdateFailedException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Entity status", e);
        }
        logger.info("Updated Entity status for {} entities in pki-manager", updatedEntityCount);
    }

    /**
     * This method is get entity based on entity name, subject DN and issuer DN
     *
     * @param entityName
     *            name of the entity for which Entity information need to be fetched
     * @param entitysubjectDN
     *            Subject DN of the entity
     * @param issuerDN
     *            Issuer name
     * @return {@link Entity} that is retrieved successfully.
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             Thrown when subject DN is in improper format.
     */
    public Entity getEntity(final String subjectDN, final String issuerDN)
            throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {

        logger.debug("Enter into getEntity method. Given parameters entitySubjectDN {}, issuerDN {}", subjectDN, issuerDN);
        EntityData entityData = null;

        try {
            final String entityName = StringUtility.getCNfromDN(subjectDN);
            entityData = getEntityByName(entityName, EntityData.class, NAME_PATH);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug("The entity is not found based on the entity name. Find the entity based on hash of subject DN.");
            entityData = getEntityBasedOnSubjectDN(subjectDN, issuerDN);
        } catch (final InvalidNameException invalidNameException) {
            logger.error(ErrorMessages.INVALID_DN);
            throw new InvalidEntityAttributeException(invalidNameException);
        }

        return entityModelMapper.toApi(entityData, MappingDepth.LEVEL_1);
    }

    private EntityData getEntityBasedOnSubjectDN(final String entitySubjectDN, final String issuerDN)
            throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException {

        logger.debug("Enter into getEntityBasedOnSubjectDN method. Given parameters entitySubjectDN {} issuerDN {}", entitySubjectDN, issuerDN);
        final String orderedString = SubjectUtils.orderSubjectDN(entitySubjectDN);
        final byte[] subjectDNHash = SubjectUtils.generateSubjectDNHash(orderedString);

        logger.debug("The subjectDNHash value is  {}", subjectDNHash);
        EntityData entityData = null;

        final List<SubjectIdentificationData> entitySubjectDatas = getSubjectIdentificationDatas(subjectDNHash);
        if (entitySubjectDatas == null) {
            logger.debug("No entity found for the given subjectDN hash value");
            throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND);
        }
        if (entitySubjectDatas.size() > maxExpectedEntitySubjectDatas) {
            logger.debug("The number of entities found based on subjectDNHash is {}", entitySubjectDatas.size());
            logger.debug("Constraint violated : Multiple entities having same subjectDN. Can't find entity based on Issuer DN.");
            throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND);
        }

        for (final SubjectIdentificationData entitySubjectData : entitySubjectDatas) {
            entityData = getEntityById(entitySubjectData.getEntityId(), EntityData.class);

            String issuerDNFromDB = null;
            final Set<CertificateData> certificateData =
                    entityData.getEntityInfoData().getIssuer().getCertificateAuthorityData().getCertificateDatas();
            for (final CertificateData data : certificateData) {
                if (data.getStatus() == CertificateStatus.ACTIVE.getId()) {
                    issuerDNFromDB = data.getSubjectDN();
                }
            }
            logger.debug("issuerDN from from database {} ", issuerDNFromDB);

            if (SubjectUtils.isDNMatched(issuerDN, issuerDNFromDB)) {
                return entityData;
            }
        }
        throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND);
    }

    /**
     * This method is used to persist the subject Identification data when a corresponding entity is added
     *
     * @param entityData
     *            entity data for which corresponding entry is persisted
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws EntityAlreadyExistsException
     *             Thrown in the case where there is already a entry for the entity
     */
    public void persistSubjectIdentificationData(final EntityData entityData) throws EntityServiceException, EntityAlreadyExistsException {
        try {
            final byte[] subjectDNhash = SubjectUtils.generateSubjectDNHash(entityData.getEntityInfoData().getSubjectDN());
            final SubjectIdentificationData subjectDNHashData = new SubjectIdentificationData();
            subjectDNHashData.setEntityId(entityData.getId());
            subjectDNHashData.setSubjectDNHash(subjectDNhash);
            persistenceManager.createEntity(subjectDNHashData);
        } catch (final javax.persistence.EntityExistsException entityExistsException) {
            logger.error("Entity Already Exists {}", entityExistsException.getMessage());
            throw new EntityAlreadyExistsException(ProfileServiceErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (final javax.persistence.TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entity {}", transactionRequiredException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final javax.persistence.PersistenceException exception) {
            logger.error("Error in creating  {}", exception.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_CREATING + "EndENtity", exception);
        }
    }

    /**
     * This method is used to delete the subject Identification data when a corresponding entity is deleted
     *
     * @param entityData
     *            entity data for which corresponding entity is deleted
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void deleteSubjectIdentificationData(final EntityData entityData) throws EntityServiceException {
        try {
            final SubjectIdentificationData subjectDNHashData = getSubjectIdentificationData(entityData.getId());
            if (subjectDNHashData != null) {
                persistenceManager.deleteEntity(subjectDNHashData);
            } else {
                logger.debug("SubjectIdentificationData is already deleted with the entity id : {}", entityData.getId());
            }
        } catch (final javax.persistence.TransactionRequiredException transactionRequiredException) {
            logger.error("Error in deleting entity {}", transactionRequiredException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "Entity", transactionRequiredException);
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("Error in deleting entity {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "Entity", persistenceException);
        }
    }

    /*
     * (non-Javadoc)
     * @see
     * com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.AbstractEntityPersistenceHandler#
     * mergeCertificateExpiryNotificationDetails(com.ericsson.oss.itpf.security.pki.manager
     * .persistence.entities.AbstractEntityData)
     */
    @Override
    protected <T extends AbstractEntityData> Set<CertificateExpiryNotificationDetailsData>
            mergeCertificateExpiryNotificationDetails(final T entityData) {

        final EntityData sourceEntityData = (EntityData) entityData;

        final String entityName = sourceEntityData.getEntityInfoData().getName();

        final Set<CertificateExpiryNotificationDetailsData> updateCertExpiryNotificationDetails =
                new HashSet<>();

        for (final CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData : sourceEntityData
                .getCertificateExpiryNotificationDetailsData()) {

            final javax.persistence.Query query =
                    persistenceManager.getEntityManager().createQuery(GET_CERTIFICATE_EXPIRY_NOTIFICATION_DETAILS_QUERY);
            query.setParameter("name", entityName);
            query.setParameter("severity", certificateExpiryNotificationDetailsData.getNotificationSeverity());
            CertificateExpiryNotificationDetailsData tempCertificateExpiryNotificationDetailsData = null;
            try {
                tempCertificateExpiryNotificationDetailsData = (CertificateExpiryNotificationDetailsData) query.getSingleResult();

                if (tempCertificateExpiryNotificationDetailsData != null) {
                    tempCertificateExpiryNotificationDetailsData
                            .setFrequencyOfNotification(certificateExpiryNotificationDetailsData.getFrequencyOfNotification());
                    tempCertificateExpiryNotificationDetailsData
                            .setPeriodBeforeExpiry(certificateExpiryNotificationDetailsData.getPeriodBeforeExpiry());
                    updateCertExpiryNotificationDetails.add(tempCertificateExpiryNotificationDetailsData);
                }
            } catch (final javax.persistence.NoResultException noResultException) {
                updateCertExpiryNotificationDetails.add(certificateExpiryNotificationDetailsData);
            }
        }
        return updateCertExpiryNotificationDetails;
    }

    /**
     * @param createdEntity
     */
    public void validateSubject(final Entity createdEntity)
            throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidSubjectException {
        if (createdEntity == null || createdEntity.getEntityInfo() == null) {
            return;
        }
        String issuerName = null;
        if (createdEntity.getEntityInfo().getIssuer() != null) {
            issuerName = createdEntity.getEntityInfo().getIssuer().getName();
        }
        String orderedString = null;
        if (createdEntity.getEntityInfo().getSubject() != null) {
            orderedString = SubjectUtils.orderSubjectDN(createdEntity.getEntityInfo().getSubject().toASN1String());
        }
        final byte[] subjectDNHash = SubjectUtils.generateSubjectDNHash(orderedString);

        List<SubjectIdentificationData> entitySubjectDatas = new ArrayList<>();
        try {
            entitySubjectDatas = getSubjectIdentificationDatas(subjectDNHash);
        } catch (final javax.persistence.PersistenceException persistenceException) {
            logger.error("Error in validating entity {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_VALIDATING + "Entity", persistenceException);
        }
        if (entitySubjectDatas != null) {
            for (final SubjectIdentificationData entitySubjectData : entitySubjectDatas) {
                if (entitySubjectData.getEntityId() != createdEntity.getEntityInfo().getId()) {
                    final EntityData entityData = getEntityById(entitySubjectData.getEntityId(), EntityData.class);
                    if (entityData.getEntityInfoData().getIssuer() != null
                            && entityData.getEntityInfoData().getIssuer().getCertificateAuthorityData().getName().equalsIgnoreCase(issuerName)
                            || entityData.getEntityInfoData().getIssuer() == null && issuerName == null) {
                        throw new InvalidSubjectException(
                                "Error while creating entity: " + createdEntity.getEntityInfo().getName() + ". Subject already used for entity: "
                                        + entityData.getEntityInfoData().getName());
                    }
                }
            }
        }
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link Entity} with Id/name Set.
     * @return {@link Entity} that is retrieved successfully.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when invalid entity type is passed.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity has invalid attribute.
     */
    @Override
    public T getEntityForImport(final T entity)
            throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final Entity inputEntity = (Entity) entity;
        final EntityData entityData = getEntitydata(inputEntity);
        return entitiesModelMapperFactory.getEntitiesExportMapper(entity.getType()).toAPIFromModel(entityData);
    }

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return Instance of {@link Entities} containing {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    @Override
    public Entities getEntitiesForImport(final EntityType entityType)
            throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {
        final Entities entities = new Entities();
        entities.setEntities((List<Entity>) getEntitiesforImport(EntityData.class, entityType));
        return entities;
    }

    /**
     * This method use to fetch EntityData with associated Issuer
     *
     * @param issuerName
     *            Name of the issuer
     * @throws CANotFoundException
     *             thrown when the provided issued not found or does not exist
     * @return List of Entityname
     */
    public List<Entity> loadEntityListByCaName(final String issuerName) throws CANotFoundException {
        return entityModelMapper.toApi(getEntityListByCaName(issuerName), MappingDepth.LEVEL_1);
    }

}
