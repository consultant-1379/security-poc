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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.EntityCategoryPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.validator.EntityCategoryValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

public class EntityCategoryConfigurationManager {

    @Inject
    Logger logger;

    @Inject
    EntityCategoryValidator entityCategoryValidator;

    @Inject
    EntityCategoryPersistenceHandler entityCategoryPersistenceHandler;

    /**
     * API for creating {@link EntityCategory}
     * 
     * @param entityCategory
     *            {@link EntityCategory} instance that is to be created.
     * 
     * @return Instance of created {@link EntityCategory}
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             thrown when category with same name already exists.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public EntityCategory createEntityCategory(EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {

        logger.debug("creating entity category with Name: {}", entityCategory.getName());

        entityCategory = validateAndCreate(entityCategory);

        logger.info("Entity category created with ID: {}", entityCategory.getId());

        logger.debug("Entity Category Created: {}", entityCategory);
        return entityCategory;
    }

    /**
     * Method to validate and create the entity category
     * 
     * @param entityCategory
     *            {@link EntityCategory} instance that is created.
     * 
     * @return Instance of created {@link EntityCategory}
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             thrown when category with same name already exists.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    private EntityCategory validateAndCreate(EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {
        logger.debug("validating entity category with Name {}", entityCategory.getName());
        entityCategoryValidator.validateCreate(entityCategory);

        entityCategory = entityCategoryPersistenceHandler.createEntityCategory(entityCategory);

        logger.debug("{} validated and created", entityCategory);

        return entityCategory;
    }

    /**
     * API for updating {@link EntityCategory}
     * 
     * @param entityCategory
     *            {@link EntityCategory} instance that is to be updated.
     * 
     * @return Instance of updated {@link EntityCategory}
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             thrown when category with same name already exists.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public EntityCategory updateEntityCategory(EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {
        logger.debug("updating entity category with ID: {}", entityCategory.getId());

        entityCategory = validateAndUpdate(entityCategory);

        logger.debug("Entity category with ID {}, Updated ", entityCategory.getId());

        return entityCategory;
    }

    /**
     * Method for validating and updating {@link EntityCategory}
     * 
     * @param entityCategory
     *            {@link EntityCategory} instance that is updated.
     * 
     * @return Instance of updated {@link EntityCategory}
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             thrown when category with same name already exists.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    private EntityCategory validateAndUpdate(EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {
        logger.debug("updating entity category with Name {}", entityCategory, entityCategory.getName());

        entityCategoryValidator.validateUpdate(entityCategory);
        entityCategory = entityCategoryPersistenceHandler.updateEntityCategory(entityCategory);

        logger.debug("{} validated and Updated", entityCategory);

        return entityCategory;
    }

    /**
     * API to get the entity category based on the entity category name.
     * 
     * @param category
     *            {@link EntityCategory} instance with name.
     * 
     * @return EntityCategory object of type {@link EntityCategory}
     * 
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category name doesn't exist.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public EntityCategory getEntityCategory(EntityCategory category) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {
        logger.debug("Retrieving {}", category.getName());

        category = entityCategoryPersistenceHandler.getEntityCategory(category);

        logger.debug("Entity Category Retrieved With ID: {}", category.getId());
        return category;
    }

    /**
     * API used to delete the entity category based on the category name.
     * 
     * @param category
     *            {@link EntityCategory} instance with name.
     * 
     * @return void
     * 
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category name doesn't exist.
     * 
     * @throws EntityCategoryInUseException
     *             Thrown when the given entity category is mapped to either entity or entity profile.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public void deleteEntityCategory(final EntityCategory category) throws EntityCategoryNotFoundException, EntityCategoryInUseException, PKIConfigurationServiceException {

        logger.debug("Deleting {}", category.getName());

        entityCategoryPersistenceHandler.deleteEntityCategory(category);
        logger.debug("{} Deleted", category.getName());
    }

    /**
     * API for checking whether the given category name exists in the database.
     * 
     * @param categoryName
     *            Entity category name
     * 
     * @return boolean returns true/false based on whether the entity category exists with the given name.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public boolean isNameAvailable(final String categoryName) throws PKIConfigurationServiceException {
        logger.debug("Checking the availability of name {}", categoryName);
        return entityCategoryPersistenceHandler.isNameAvailable(categoryName.trim());
    }

    /**
     * API for retrieving all the entity categories existing in the database.
     * 
     * @return List of {@link EntityCategory}
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public List<EntityCategory> getEntityCategories() throws PKIConfigurationServiceException {
        logger.debug("Retrieving all entity categories in the database");

        final List<EntityCategory> entityCategories = entityCategoryPersistenceHandler.getCategories();

        logger.debug("{}s Retrieved", entityCategories);

        return entityCategories;
    }

}
