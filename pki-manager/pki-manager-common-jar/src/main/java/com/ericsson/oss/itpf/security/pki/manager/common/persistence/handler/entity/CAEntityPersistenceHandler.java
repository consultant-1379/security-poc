/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.EntityStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.DefaultCertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.EntityStatusUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyDeletedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;

/**
 * This class is responsible for {@link CAEntity} DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model {@link CAEntity} to JPA Entity {@link CAEntityData}</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model {@link CAEntity} if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractEntity} i.e., {@link CAEntity}.
 */
@EntityQualifier(EntityType.CA_ENTITY)
public class CAEntityPersistenceHandler<T extends AbstractEntity> extends AbstractEntityPersistenceHandler<T> {

    @Inject
    DefaultCertificateExpiryNotificationDetails defaultCertExpiryNotificationDetails;

    private final static String CA_NAME_PATH = "certificateAuthorityData.name";

    private final static String trustProfileQueryForExternalCAs = "select t from TrustProfileData t join t.externalCAs c where t.active in(:is_active) and c.id=:externalca_id";
    private final static String trustProfileQueryForInternalCAs = "select t from TrustProfileData t join t.trustCAChains c where t.active in(:is_active) and c.trustChainId.caEntityData.id=:internalca_id";
    private static final String GET_CERTIFICATE_EXPIRY_NOTIFICATION_DETAILS_QUERY = "select c from CertificateExpiryNotificationDetailsData c where c.id in(select cendd.id from CAEntityData ced inner join ced.certificateExpiryNotificationDetailsData cendd  WHERE ced.certificateAuthorityData.name = :name and cendd.notificationSeverity= :severity  and ced.externalCA = false) ORDER BY c.id DESC ";
    private static final String updateCAEntityStatusToInactiveNativeQuery = "update caentity SET status_id=3 where id not in (select distinct ca_cert.ca_id from ca_certificate ca_cert where ca_cert.certificate_id in (select cert.id from certificate cert where cert.status_id in (1,4))) and status_id = 2";
    private static final String GET_CA_ENTITIES_COUNT_QUERY = "select count(*) from CAEntityData e where e.externalCA = :externalCA";
    private static final String queryForFetchCAEntitiesByStatus = "select id,name from caentity where status_id= :status_id";

    /**
     * This method is used for create operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Persist into DB.</li>
     * <li>Retrieve created Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity} that is to be persisted.
     * @return {@link CAEntity} that is persisted successfully.
     *
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws InvalidEntityException
     *             thrown when Entity Type other than CAEntity/Entity is given.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity has invalid attribute.
     * @throws InvalidProfileAttributeException
     *             thrown when Entity has invalid attribute.
     */
    @Override
    public T createEntity(final T entity) throws EntityAlreadyExistsException, EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException,
    InvalidProfileAttributeException {
        final CAEntity caEntity = (CAEntity) entity;
        final String name = caEntity.getCertificateAuthority().getName();

        if (ValidationUtils.isNullOrEmpty(entity.getCertificateExpiryNotificationDetails())) {
            entity.setCertificateExpiryNotificationDetails(defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails());
        }

        persistEntity(entity);

        final CAEntityData caEnData = getEntityByName(name, CAEntityData.class, CA_NAME_PATH);
        return getEntitiesMapperv1(entity.getType()).toApi(caEnData, MappingDepth.LEVEL_0);
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
     *            {@link CAEntity} with Id/name Set.
     *
     * @return {@link CAEntity} that is retrieved successfully.
     *
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when EntityType other than CAEntity/Entity is given.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     */
    @Override
    public T getEntity(final T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        final CAEntity cAEntity = (CAEntity) entity;

        final CAEntityData caEntityData = getCAEntitydata(cAEntity);
        return getEntitiesMapperv1(entity.getType()).toApi(caEntityData, MappingDepth.LEVEL_1);
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.This method doesnot map the the active and inactive certificates of the entity</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity} with Id/name Set.
     *
     * @return {@link CAEntity} that is retrieved successfully.
     *
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             Thrown when given CA Entity is not Found.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when name or id passed are invalid.
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile attribute is invalid.
     */
    public T getEntityForCertificateGeneration(final T entity) throws CAEntityNotInternalException, CANotFoundException, EntityNotFoundException, EntityServiceException,
    InvalidEntityAttributeException, InvalidProfileAttributeException {

        final CAEntity cAEntity = (CAEntity) entity;

        final CAEntityData caEntityData = getCAEntitydata(cAEntity);
        return getEntitiesMapperv1(EntityType.CA_ENTITY).toApi(caEntityData, MappingDepth.LEVEL_1);
    }

    /**
     * @param caEntity
     *            {@link CAEntity} that has ID/Name set.
     * @return {@link CAEntityData} that is retrieved from DB based on given ID/Name.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when name or id passed are invalid.
     */
    public CAEntityData getCAEntitydata(final CAEntity caEntity) throws EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        final long id = caEntity.getCertificateAuthority().getId();
        final String name = caEntity.getCertificateAuthority().getName();
        return getEntityData(id, name, CAEntityData.class, CA_NAME_PATH);

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
     *            {@link CAEntity} that is to be deleted.
     *
     * @return {@link ProfileManagerResponse} with status messages set.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity is invalid.
     */
    @Override
    public void deleteEntity(final T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        final CAEntity cAEntity = (CAEntity) entity;
        final String name = cAEntity.getCertificateAuthority().getName();

        final CAEntityData caEntityData = getCAEntitydata(cAEntity);

        try {
            if (caEntityData.getCertificateAuthorityData().getStatus() == CAStatus.NEW.getId()) {
                persistenceManager.deleteEntity(caEntityData);
            } else {
                caEntityData.getCertificateAuthorityData().setStatus(CAStatus.DELETED.getId());
                persistenceManager.updateEntity(caEntityData);
            }
        } catch (final javax.persistence.TransactionRequiredException e) {
            logger.error("Error in deleting CA entity {}. {}", name, e.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "CA Entity.", e);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in deleting CA entity {}. {}", name, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "CA Entity.", persistenceException);
        }
    }

    /**
     * This method is used to check Entity is deletable or not based on status.
     *
     * @throws EntityAlreadyDeletedException
     *             Thrown when the Entity is already in deleted state.
     * @throws EntityInUseException
     *             Thrown when the Entity is in Active state.
     * @throws EntityNotFoundException
     *             Thrown when the given entity is not found in system.
     * @throws EntityServiceException
     *             Thrown when Internal error occures in system.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity is invalid.
     */
    @Override
    public boolean isDeletable(final T entity) throws EntityAlreadyDeletedException, EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        boolean isDeletable = false;

        final CAEntity cAEntity = (CAEntity) entity;
        final CAEntityData caEntityData = getCAEntitydata(cAEntity);
        if (isEntityNotUsed(caEntityData)) {

            final Integer caStatus = caEntityData.getCertificateAuthorityData().getStatus();

            switch (CAStatus.getStatus(caStatus)) {
            case NEW:
            case INACTIVE: {
                isDeletable = true;
                break;
            }
            case DELETED: {
                logger.error("CAEntity is already deleted");
                throw new EntityAlreadyDeletedException("CAEntity is already deleted");
            }
            case ACTIVE: {
                logger.error("CAEntity has a valid certificate. It cannot be deleted.");
                throw new EntityInUseException("CAEntity has a valid certificate. It cannot be deleted.");
            }
            }
        }
        return isDeletable;
    }

    private boolean isEntityNotUsed(final CAEntityData caEntityData) throws EntityInUseException, EntityServiceException {

        boolean isEntityNotUsed = false;
        boolean hasCertProfile = false;
        boolean hasTrustProfile = false;

        final List<String> mappedCertificateProfileNames = getCertificateProfileNames(caEntityData);
        final List<String> mappedTrustProfileNames = getTrustProfileNames(caEntityData);

        if (mappedCertificateProfileNames.size() > 0) {
            hasCertProfile = true;
        }

        if (mappedTrustProfileNames.size() > 0) {
            hasTrustProfile = true;
        }

        if (hasTrustProfile) {
            throw new EntityInUseException(ProfileServiceErrorCodes.CAENTITY_IN_USE + " by Trust Profiles: " + mappedTrustProfileNames);
        } else if (hasCertProfile) {
            throw new EntityInUseException(ProfileServiceErrorCodes.CAENTITY_IN_USE + " by Certificate Profiles: " + mappedCertificateProfileNames);
        } else {
            isEntityNotUsed = true;
        }

        return isEntityNotUsed;
    }

    private List<String> getCertificateProfileNames(final CAEntityData caEntityData) throws EntityServiceException {
        final List<String> certificateProfileNames = new ArrayList<String>();

        List<CertificateProfileData> certificateProfileDatas = new ArrayList<CertificateProfileData>();

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("issuerData", caEntityData);
        input.put("active", true);

        try {
            certificateProfileDatas = persistenceManager.findEntitiesWhere(CertificateProfileData.class, input);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in deleting CA entity. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "CA Entity.", persistenceException);
        }

        for (int i = 0; i < certificateProfileDatas.size(); i++) {
            if (certificateProfileDatas.get(i).isActive()) {
                certificateProfileNames.add(certificateProfileDatas.get(i).getName());
            }
        }

        return certificateProfileNames;
    }

    private List<String> getTrustProfileNames(final CAEntityData caEntityData) throws EntityServiceException {
        final List<String> trustProfileNamesWithUseAsExternalCAs = getTrustProfileNamesWithUseAsExternalCAs(caEntityData);
        final List<String> trustProfileNamesWithUseAsInternalCAs = getTrustProfileNamesWithUseAsInternalCAs(caEntityData);

        final List<String> trustProfileNames = new ArrayList<String>();
        trustProfileNames.addAll(trustProfileNamesWithUseAsExternalCAs);

        for (final String trustProfileName : trustProfileNamesWithUseAsInternalCAs) {

            if (!trustProfileNames.contains(trustProfileName)) {
                trustProfileNames.add(trustProfileName);
            }
        }

        return trustProfileNames;
    }

    public List<String> getTrustProfileNamesWithUseAsExternalCAs(final CAEntityData caEntityData) throws EntityServiceException {
        final List<String> trustProfileNames = new ArrayList<String>();

        List<TrustProfileData> trustProfileDatas = new ArrayList<TrustProfileData>();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("externalca_id", caEntityData.getId());
        attributes.put("is_active", true);

        try {
            trustProfileDatas = persistenceManager.findEntitiesByAttributes(trustProfileQueryForExternalCAs, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in deleting CA entity. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "CA Entity.", persistenceException);
        }

        for (int i = 0; i < trustProfileDatas.size(); i++) {
            if (trustProfileDatas.get(i).isActive()) {
                trustProfileNames.add(trustProfileDatas.get(i).getName());
            }
        }

        return trustProfileNames;
    }

    private List<String> getTrustProfileNamesWithUseAsInternalCAs(final CAEntityData caEntityData) throws EntityServiceException {
        final List<String> trustProfileNames = new ArrayList<String>();

        List<TrustProfileData> trustProfileDatas = new ArrayList<TrustProfileData>();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("internalca_id", caEntityData.getId());
        attributes.put("is_active", true);

        try {
            trustProfileDatas = persistenceManager.findEntitiesByAttributes(trustProfileQueryForInternalCAs, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in deleting CA entity. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING + "CA Entity.", persistenceException);
        }

        for (int i = 0; i < trustProfileDatas.size(); i++) {
            if (trustProfileDatas.get(i).isActive()) {
                trustProfileNames.add(trustProfileDatas.get(i).getName());
            }
        }

        return trustProfileNames;
    }

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return Instance of {@link Entities} containing {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @Override
    public Entities getEntities(final EntityType entityType) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final Entities entities = new Entities();
        entities.setCAEntities((List<CAEntity>) getEntities(CAEntityData.class, entityType));
        return entities;
    }

    /**
     * This method is used check the availability of Name used for {@link CAEntity}
     *
     * @param name
     *            name of entity to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     *
     */
    @Override
    public boolean isNameAvailable(final String name) throws EntityServiceException {
        return isNameAvailable(name, CAEntityData.class, CA_NAME_PATH);
    }

    @Override
    public List<T> getEntitiesByCategory(final EntityCategory entityCategory, final Boolean isIssuerDataRequired)
            throws EntityCategoryException, EntityNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * This method finds the given ca entity data in DB and merges with it
     *
     * @param entityData
     *            ca entity data that has to be found and merged
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given EntityID.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public <E extends AbstractEntityData> E findAndMergeEntityData(final E entityData) throws EntityNotFoundException, EntityServiceException {
        final CAEntityData sourceCAEntityData = (CAEntityData) entityData;
        final CAEntityData targetCAEntityData = getEntityById(sourceCAEntityData.getId(), CAEntityData.class);

        final CAEntityData mergedCAEntityData = mergeEntityData(sourceCAEntityData, targetCAEntityData);

        return (E) mergedCAEntityData;
    }

    private CAEntityData mergeEntityData(final CAEntityData sourceCAEntityData, final CAEntityData targetCAEntityData) {

        final CertificateAuthorityData sourceCertificateAuthorityData = sourceCAEntityData.getCertificateAuthorityData();
        final CertificateAuthorityData targetCertificateAuthorityData = targetCAEntityData.getCertificateAuthorityData();

        targetCertificateAuthorityData.setName(sourceCertificateAuthorityData.getName());
        targetCertificateAuthorityData.setRootCA(isRootCA(sourceCAEntityData.getEntityProfileData()));
        targetCertificateAuthorityData.setSubjectAltName(sourceCertificateAuthorityData.getSubjectAltName());
        targetCertificateAuthorityData.setSubjectDN(sourceCertificateAuthorityData.getSubjectDN());
        targetCertificateAuthorityData.setIssuer(sourceCertificateAuthorityData.getIssuer());
        targetCertificateAuthorityData.setPublishToCDPS(sourceCertificateAuthorityData.isPublishToCDPS());

        if (ValidationUtils.isNullOrEmpty(targetCertificateAuthorityData.getCrlGenerationInfo()) && !ValidationUtils.isNullOrEmpty(sourceCertificateAuthorityData.getCrlGenerationInfo())) {
            targetCertificateAuthorityData.setCrlGenerationInfo(sourceCertificateAuthorityData.getCrlGenerationInfo());
        }

        targetCAEntityData.setCertificateAuthorityData(targetCertificateAuthorityData);

        targetCAEntityData.setEntityProfileData(sourceCAEntityData.getEntityProfileData());
        targetCAEntityData.setKeyGenerationAlgorithm(sourceCAEntityData.getKeyGenerationAlgorithm());
        targetCAEntityData.setPublishCertificatetoTDPS(sourceCAEntityData.isPublishCertificatetoTDPS());

        if (!ValidationUtils.isNullOrEmpty(sourceCAEntityData.getCertificateExpiryNotificationDetailsData())) {
            final Set<CertificateExpiryNotificationDetailsData> updateCertExpiryNotificationDetails = mergeCertificateExpiryNotificationDetails(sourceCAEntityData);
            targetCAEntityData.getCertificateExpiryNotificationDetailsData().clear();
            targetCAEntityData.getCertificateExpiryNotificationDetailsData().addAll(updateCertExpiryNotificationDetails);
        }

        return targetCAEntityData;
    }

    private boolean isRootCA(final EntityProfileData entityProfileData) {
        return entityProfileData.getCertificateProfileData().getIssuerData() == null ? true : false;
    }

    /**
     * This method returns count of CAEntities, applying filter criteria, if any specified.
     *
     * @param entitiesFilter
     *            criteria based on which entities have to be filtered
     * @return count of entities matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public int getEntitiesCountByFilter(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        int count = 0;
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("externalCA", false);
        try {
            final String query = buildDynamicQuery(GET_CA_ENTITIES_COUNT_QUERY, entitiesFilter, attributes);
            logger.info("Query in getEntitiesCountWithFilter: {}" , query);
            count = (int) persistenceManager.findEntitiesCountByAttributes(query, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of CAEntities that match with given filter criteria. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "CA Entity.", persistenceException);
        }

        return count;
    }

    private String buildDynamicQuery(final String queryForCaEntities, final EntitiesFilter entitiesFilter, final Map<String, Object> attributes) {
        final StringBuilder query = new StringBuilder(queryForCaEntities);

        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getName())) {
            query.append(" and lower(e.certificateAuthorityData.name) like lower(:caEntityName) ");
            attributes.put("caEntityName", entitiesFilter.getName());
        }
        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getStatus())) {
            query.append(" and e.certificateAuthorityData.status in (:statusList) ");
            attributes.put("statusList", EntityStatusUtils.getCAEntityStatusList(entitiesFilter));
        }

        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getCertificateAssigned())) {
            query.append("  and (select count(certificates) from e.certificateAuthorityData.certificateDatas certificates) = :certificateCount ");
            attributes.put("certificateCount", (long) entitiesFilter.getCertificateAssigned());
        }

        return query.toString();

    }

    /**
     * This method fetches the list of ca entities based on given ca status value
     *
     * @param caStatus
     *            the integer value of status of caentity
     *
     * @return List of ca entities which has given ca status
     *
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @Override
    public List<T> getEntitiesByStatus(final int caStatus) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        List<CAEntityData> caEntityDatas = null;
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("certificateAuthorityData.status", caStatus);
        try {
            caEntityDatas = persistenceManager.findEntitiesWhere(CAEntityData.class, attributes);
            if (ValidationUtils.isNullOrEmpty(caEntityDatas)) {
                logger.error("There are no CA Entities");
                return null;
            }
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving CAEntity. {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING, persistenceException);
        }
        return getEntitiesMapper(EntityType.CA_ENTITY).toAPIModelList(caEntityDatas);
    }

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     *
     * @throws EntityStatusUpdateFailedException
     */
    public void updateCAEntityStatusToInactive() throws EntityStatusUpdateFailedException {
        int updatedEntityCount = 0;
        final javax.persistence.Query query = persistenceManager.getEntityManager().createNativeQuery(updateCAEntityStatusToInactiveNativeQuery);
        try {
            updatedEntityCount = query.executeUpdate();

        } catch (PersistenceException | IllegalStateException e) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CAEntity status " + e.getMessage() + e.getCause() + " | " + e);
            throw new EntityStatusUpdateFailedException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CAEntity status", e);
        }
        logger.info("Updated CAEntity status for {} entities in pki-manager", updatedEntityCount);

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
     */
    public List<CAEntity> fetchCAEntitiesIdAndNameByStatus(final CAStatus caStatus, final boolean externalCARequired) throws EntityServiceException {
        List<CAEntity> caEntities = null;
        final StringBuilder query = new StringBuilder(queryForFetchCAEntitiesByStatus);
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("status_id", caStatus.getId());
        if (!externalCARequired) {
            query.append(" and is_external_ca = :externalCA ");
            attributes.put("externalCA", false);
        }
        try {
            // To-Do : native query has to be migrated to JPQL - http://jira-nam.lmera.ericsson.se/browse/TORF-114083
            final List<Object[]> entities = persistenceManager.findEntitiesByNativeQuery(query.toString(), attributes);

            caEntities = mapToCAEntities(entities);
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.ERROR_GETTING_ACTIVE_ISSUERS, persistenceException.getMessage());
            throw new EntityServiceException(ErrorMessages.ERROR_GETTING_ACTIVE_ISSUERS + persistenceException);
        }

        return caEntities;
    }

    private List<CAEntity> mapToCAEntities(final List<Object[]> entities) {
        final List<CAEntity> caEntities = new ArrayList<CAEntity>();

        for (final Object[] entity : entities) {
            final CAEntity caEntity = new CAEntity();
            final CertificateAuthority certificateAuthority = new CertificateAuthority();

            certificateAuthority.setId(((BigInteger) entity[0]).longValue());
            certificateAuthority.setName((String) entity[1]);

            caEntity.setCertificateAuthority(certificateAuthority);
            caEntities.add(caEntity);
        }

        return caEntities;
    }

    @Override
    protected <T extends AbstractEntityData> Set<CertificateExpiryNotificationDetailsData> mergeCertificateExpiryNotificationDetails(final T entityData) {

        final CAEntityData sourceCAEntityData = (CAEntityData) entityData;

        final String caEntityName = sourceCAEntityData.getCertificateAuthorityData().getName();

        final Set<CertificateExpiryNotificationDetailsData> updateCertExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetailsData>();

        for (final CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData : sourceCAEntityData.getCertificateExpiryNotificationDetailsData()) {
            try {

                final Query query = persistenceManager.getEntityManager().createQuery(GET_CERTIFICATE_EXPIRY_NOTIFICATION_DETAILS_QUERY);
                query.setParameter("name", caEntityName);
                query.setParameter("severity", certificateExpiryNotificationDetailsData.getNotificationSeverity());
                CertificateExpiryNotificationDetailsData tempCertificateExpiryNotificationDetailsData = null;

                tempCertificateExpiryNotificationDetailsData = (CertificateExpiryNotificationDetailsData) query.getSingleResult();

                if (tempCertificateExpiryNotificationDetailsData != null) {
                    tempCertificateExpiryNotificationDetailsData.setFrequencyOfNotification(certificateExpiryNotificationDetailsData.getFrequencyOfNotification());
                    tempCertificateExpiryNotificationDetailsData.setPeriodBeforeExpiry(certificateExpiryNotificationDetailsData.getPeriodBeforeExpiry());
                    updateCertExpiryNotificationDetails.add(tempCertificateExpiryNotificationDetailsData);
                }
            } catch (IllegalArgumentException | NoResultException exception) {
                updateCertExpiryNotificationDetails.add(certificateExpiryNotificationDetailsData);
            }

        }
        return updateCertExpiryNotificationDetails;

    }

    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler#getEntitiesSummaryByCategory(com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory)
     */
    @Override
    public List<T> getEntitiesSummaryByCategory(final EntityCategory entityCategory) throws EntityCategoryNotFoundException, EntityNotFoundException,
    EntityServiceException, InvalidEntityAttributeException, InvalidEntityCategoryException {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * This method retrieves Entity used for update Entity operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity} with Id/name Set.
     * @return {@link CAEntity} that is retrieved successfully.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when EntityType other than CAEntity/Entity is given.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     */
    @Override
    public T getEntityForImport(final T entity)
            throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final CAEntity cAEntity = (CAEntity) entity;
        final CAEntityData caEntityData = getCAEntitydata(cAEntity);
        return entitiesModelMapperFactory.getEntitiesExportMapper(entity.getType()).toAPIFromModel(caEntityData);
    }

    /**
     * This method is used for retrieving Entities in bulk used for import entity operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return Instance of {@link Entities} containing {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @Override
    public Entities getEntitiesForImport(final EntityType entityType)
            throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {
        final Entities entities = new Entities();
        entities.setCAEntities((List<CAEntity>) getEntitiesforImport(CAEntityData.class, entityType));
        return entities;
    }
}
