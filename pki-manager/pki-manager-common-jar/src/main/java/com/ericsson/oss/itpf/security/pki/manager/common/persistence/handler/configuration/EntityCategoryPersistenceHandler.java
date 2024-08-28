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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.EntityExistsException;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.SearchType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityCategoryMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is responsible for DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model to JPA Entity</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model if required</li>
 * </ul>
 *
 */
public class EntityCategoryPersistenceHandler {

    @Inject
    private Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    EntityCategoryMapper entityCategoryMapper;

    private static final String ENTITY_CATEGORY_ID = "entityCategoryData";

    private static final String NAME_PATH = "name";

    /**
     * This method is used for create operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Persist into DB.</li>
     * <li>Retrieve created Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entityCategory
     *            {@link EntityCategory} that is to be persisted.
     * @return {@link EntityCategory} that is persisted successfully.
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             thrown when the given category already exists in system.
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    public EntityCategory createEntityCategory(final EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, PKIConfigurationServiceException {
        EntityCategory category;
        try {
            final EntityCategoryData categoryData = entityCategoryMapper.fromAPIToModel(entityCategory);
            persistenceManager.createEntity(categoryData);
            final EntityCategoryData categoryDataCreated = persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME_PATH);

            category = entityCategoryMapper.toAPIFromModel(categoryDataCreated);
        } catch (final EntityExistsException entityExistsException) {
            logger.error("Entity Category Already Exists {}", entityExistsException.getMessage());
            throw new EntityCategoryAlreadyExistsException(ErrorMessages.ENTITY_CATEGORY_EXISTS_ALREADY, entityExistsException);
        } catch (final PersistenceException exception) {
            logger.error("Error in creating entity category {}", exception.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_CREATING_ENTITY_CATEGORY, exception);
        }
        return category;

    }

    /**
     * This method is used for update operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Persist into DB.</li>
     * <li>Retrieve updated Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entityCategory
     *            {@link EntityCategory} that is to be persisted.
     *
     * @return {@link EntityCategory} that is persisted successfully.
     *
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    public EntityCategory updateEntityCategory(EntityCategory entityCategory) throws PKIConfigurationServiceException {
        try {
            final EntityCategoryData categoryData = entityCategoryMapper.fromAPIToModel(entityCategory);
            persistenceManager.updateEntity(categoryData);
            final EntityCategoryData categoryDataUpdated = persistenceManager.findEntityByName(categoryData.getClass(), entityCategory.getName(), NAME_PATH);
            entityCategory = entityCategoryMapper.toAPIFromModel(categoryDataUpdated);
        } catch (final PersistenceException exception) {
            logger.error("Error in updating entity category. {}", exception.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_UPDATING_ENTITY_CATEGORY, exception);
        }
        return entityCategory;
    }

    /**
     * This method is used to retrieve the EntityCategory from the system.
     * 
     * @param category
     *
     * @return EntityCategory object
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when no entity category found with given ID/Name.
     *
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    public EntityCategory getEntityCategory(final EntityCategory category) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {
        final EntityCategoryData entityCategoryData = getEntityCategoryData(category, EntityCategoryData.class);
        return entityCategoryMapper.toAPIFromModel(entityCategoryData);
    }

    /**
     * Retrieve the entity category based on Name/Id/Both. This method calls the respective method to retrieve a entity category based on the input provided.
     *
     * @param entityCategory
     *            entity category object with Id/Name set.
     * @param entityCategoryDataClass
     *            JPA Entity Class
     * @return Instance of {@link EntityCategoryData} retrieved.
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when no entity category found with given ID/Name.
     *
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    protected EntityCategoryData getEntityCategoryData(final EntityCategory entityCategory, final Class<EntityCategoryData> entityCategoryDataClass) throws EntityCategoryNotFoundException,
            PKIConfigurationServiceException {
        EntityCategoryData entityCategoryData;

        final SearchType searchType = getEntityCategorySearchType(entityCategory.getId(), entityCategory.getName());

        switch (searchType) {
        case ID:
            entityCategoryData = getEntityCategoryById(entityCategory.getId(), entityCategoryDataClass);
            break;
        case NAME:
            entityCategoryData = getEntityCategoryByName(entityCategory.getName());
            break;
        case BOTH:
            entityCategoryData = getEntityCategoryByNameAndId(entityCategory.getId(), entityCategory.getName());
            break;
        default:
            throw new IllegalArgumentException("Invalid entity category Id or Name");
        }

        return entityCategoryData;
    }

    /**
     * @param id
     *            entity category id
     * @param name
     *            entity category name
     * @param entityCategoryDataClass
     *            JPA Entity Class
     * @return Instance of {@link EntityCategoryData} retrieved.
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when no entity category found with given ID/Name.
     *
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system
     */
    private EntityCategoryData getEntityCategoryByNameAndId(final long id, final String name) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {
        EntityCategoryData entityCategoryData = null;
        try {
            entityCategoryData = persistenceManager.findEntityByIdAndName(EntityCategoryData.class, id, name, NAME_PATH);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Entity category. {}", persistenceException.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_RETRIEVING_ENTITY_CATEGORY, persistenceException);
        }
        if (entityCategoryData == null) {
            throw new EntityCategoryNotFoundException(ErrorMessages.NO_ENTITY_CATEGORY_FOUND_WITH_ID_AND_NAME + id + " " + name);
        }
        return entityCategoryData;
    }

    /**
     * This method is used for retrieve operation based on name. It Does the following operation:
     * <ul>
     * <li>Get the Id.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param name
     *            name, using which JPA Entity to be retrieved
     *
     * @param name
     *            entity category name
     *
     * @param entityCategoryDataClass
     *            JPA Entity Class
     *
     * @return Instance of {@link EntityCategoryData} retrieved successfully.
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when no entity category found with given ID/Name.
     *
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    private EntityCategoryData getEntityCategoryByName(final String name) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {
        EntityCategoryData entityCategoryData = null;
        try {
            entityCategoryData = persistenceManager.findEntityByName(EntityCategoryData.class, name, NAME_PATH);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Entity Category. {}", persistenceException.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_RETRIEVING_ENTITY_CATEGORY, persistenceException);
        }
        if (entityCategoryData == null) {
            logger.error("Entity Category not found with given name {}", name);
            throw new EntityCategoryNotFoundException(ErrorMessages.NO_ENTITY_CATEGORY_FOUND_WITH_NAME + name);
        }
        return entityCategoryData;
    }

    /**
     * get the {@link SearchType} whether the entity category needs to be retrieved based on id or name.
     *
     * @param id
     *            id, using which JPA Entity to be retrieved
     * @param name
     *            name, using which JPA Entity to be retrieved
     * @return {@link SearchType}
     */
    protected SearchType getEntityCategorySearchType(final long id, final String name) {
        if (id == 0 && name == null) {
            logger.error("Invalid Arguments: Atleast id or name should be specified.");
            throw new IllegalArgumentException(ErrorMessages.ID_OR_NAME_SHOULD_PRESENT);
        }

        if (id != 0 && name != null) {
            return SearchType.BOTH;
        } else {
            if (id != 0) {
                return SearchType.ID;
            } else {
                return SearchType.NAME;
            }
        }
    }

    /**
     * This method is used for retrieve operation based on id. It Does the following operation:
     * <ul>
     * <li>Get the Id.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param id
     *            id, using which JPA Entity to be retrieved
     *
     * @param entityCategoryDataClass
     *            Class of JPA Entity EntityCategoryData
     * @return EntityCategory that is retrieved successfully.
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when no entity category found with given ID/Name.
     *
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    @SuppressWarnings("unchecked")
    protected EntityCategoryData getEntityCategoryById(final long id, final Class<EntityCategoryData> entityCategoryDataClass) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {
        EntityCategoryData entityCategoryData = null;
        try {
            entityCategoryData = persistenceManager.findEntity(entityCategoryDataClass, id);
        } catch (final PersistenceException exception) {
            logger.error("Error in retrieving entity category. {}", exception.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_RETRIEVING_ENTITY_CATEGORY, exception);
        }

        if (entityCategoryData == null) {
            throw new EntityCategoryNotFoundException(ErrorMessages.NO_ENTITY_CATEGORY_FOUND_WITH_ID + id);
        }
        return entityCategoryData;
    }

    /**
     * This method is used to Delete the EntityCategory
     * 
     * @param category
     *            Entity category object
     * @throws EntityCategoryInUseException
     *             thrown when any entity is mapped to the category
     * @throws EntityCategoryNotFoundException
     *             Thrown when no entity category found with given input.
     * @throws PKIConfigurationServiceException
     *             thrown when there is any exception in transactions.
     */
    public void deleteEntityCategory(final EntityCategory category) throws EntityCategoryInUseException, EntityCategoryNotFoundException, PKIConfigurationServiceException {

        final EntityCategoryData entityCategoryData = getEntityCategoryData(category, EntityCategoryData.class);
        try {
            checkEntityCategoryMapped(entityCategoryData);
            persistenceManager.deleteEntity(entityCategoryData);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error occurred while deleting Entity Category. {}", persistenceException.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.ERROR_OCCURED_WHILE_DELETING_ENTITY_CATEGORY, persistenceException);
        }

    }

    private void checkEntityCategoryMapped(final EntityCategoryData entityCategoryData) throws EntityCategoryInUseException, PKIConfigurationServiceException {

        List<EntityData> entityDatas;
        List<EntityProfileData> entityProfileDatas;
        final Map<String, Object> entityAttributes = new HashMap<String, Object>();

        entityAttributes.put(ENTITY_CATEGORY_ID, entityCategoryData);

        final HashMap<String, Object> entityProfileAttributes = new HashMap<String, Object>();
        final List<String> entityNames = new ArrayList<String>();
        final List<String> entityProfileNames = new ArrayList<String>();

        entityProfileAttributes.put(ENTITY_CATEGORY_ID, entityCategoryData);

        try {
            entityDatas = persistenceManager.findEntitiesWhere(EntityData.class, entityAttributes);
            if (entityDatas.size() > 0) {
                final Iterator<EntityData> iterator = entityDatas.iterator();

                while (iterator.hasNext()) {
                    final EntityData entityData = iterator.next();
                    final EntityStatus status = entityData.getEntityInfoData().getStatus();
                    if (!(status.getId() == 5)) {
                        entityNames.add(entityData.getEntityInfoData().getName());
                    }
                }

            }

            entityProfileDatas = persistenceManager.findEntitiesWhere(EntityProfileData.class, entityProfileAttributes);

            if (entityProfileDatas.size() > 0) {

                final Iterator<EntityProfileData> iterator = entityProfileDatas.iterator();

                while (iterator.hasNext()) {
                    final EntityProfileData entityProfileData = iterator.next();
                    entityProfileNames.add(entityProfileData.getName());
                }
            }

        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while getting linked entity Profiles. {}", persistenceException.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_RETRIEVING_ENTITY_CATEGORY, persistenceException);
        }
        if (entityNames.size() > 0 || entityProfileDatas.size() > 0) {

            throw new EntityCategoryInUseException(ErrorMessages.ENTITY_CATEGORY_IN_USE_BY_ENTTIY + entityNames + "  " + entityProfileNames);
        }
    }

    /**
     * This method used to check the availability of the Category in the system.
     * 
     * @param name
     *            entity name to be checked
     * @return true if the entity with the name exists otherwise false.
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    public boolean isNameAvailable(final String name) throws PKIConfigurationServiceException {
        try {
            getEntityCategoryByName(name);
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(ErrorMessages.NO_ENTITY_CATEGORY_FOUND_WITH_NAME, entityCategoryNotFoundException);
            return true;
        }

        return false;
    }

    /**
     * This method is Used to retreive the List of Entity Categories
     * 
     * @return
     * @throws PKIConfigurationServiceException
     *             Thrown when any internal error occurs in system.
     */
    public List<EntityCategory> getCategories() throws PKIConfigurationServiceException {
        final List<EntityCategory> entityCategories = new ArrayList<EntityCategory>();
        try {
            final List<EntityCategoryData> entityCategoryDataList = persistenceManager.getAllEntityItems(EntityCategoryData.class);

            for (final EntityCategoryData entityCategoryData : entityCategoryDataList) {
                final EntityCategory category = entityCategoryMapper.toAPIFromModel(entityCategoryData);
                entityCategories.add(category);
            }
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving entity categories. {}", persistenceException.getMessage());
            throw new PKIConfigurationServiceException(ErrorMessages.OCCURED_IN_RETRIEVING_ENTITY_CATEGORY, persistenceException);
        }
        return entityCategories;
    }

}
