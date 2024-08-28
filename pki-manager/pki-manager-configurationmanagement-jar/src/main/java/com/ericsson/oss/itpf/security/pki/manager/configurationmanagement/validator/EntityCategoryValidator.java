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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.validator;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Table;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;

public class EntityCategoryValidator {

    @Inject
    private Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    private static final String NAME_REGEX = "^[a-zA-Z0-9_ -]{3,255}$";

    private static final String NAME_PATH = "name";

    /**
     * This method validates the entity category attributes provided as part of create request
     * 
     * @param entityCategory
     *            entity category object received as part of create request
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             when entity category already exists in the database.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             if any exception arises when fetching entity categories from database
     */
    public <T> void validateCreate(final EntityCategory category) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {
        if (category == null) {
            logger.error("Entity category cannot be null");
            throw new InvalidEntityCategoryException(ErrorMessages.REQUIRED_ENTITY_CATEGORY);
        }
        final EntityCategory entityCategory = (EntityCategory) category;
        final long DEFAULT_PROFILE_ID = 0;
        entityCategory.setId(DEFAULT_PROFILE_ID);
        validateEntityCategory(entityCategory, OperationType.CREATE);
    }

    /**
     * This method validates the entity category attributes
     * 
     * @param entityCategory
     *            entity category object received as part of create request
     * @param operationType
     *            whether the operation type is create/update
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             when entity category already exists in the database.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             if any exception arises when fetching entity categories from database
     */
    private void validateEntityCategory(final EntityCategory entityCategory, final OperationType operationType) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException,
            PKIConfigurationServiceException {
        logger.debug("Validating entity category {}", entityCategory);

        if (operationType.equals(OperationType.CREATE)) {
            validateEntityCategoryNameFormat(entityCategory, operationType, EntityCategoryData.class);
        } else {
            EntityCategoryData entityCategoryDataFromDB = null;
            try {
                validateEntityCategoryNameFormat(entityCategory, operationType, EntityCategoryData.class);
                entityCategoryDataFromDB = persistenceManager.findEntity(EntityCategoryData.class, entityCategory.getId());
            } catch (final PersistenceException persistenceException) {
                logger.error("No entity category found..error in Checking DB!");
                throw new PKIConfigurationServiceException(ErrorMessages.NO_ENTITY_CATEGORY_FOUND_WITH_ID, persistenceException);
            }

            if (entityCategoryDataFromDB == null) {
                logger.error("No entity category found..error in Checking DB!");
                throw new InvalidEntityCategoryException(ErrorMessages.NO_ENTITY_CATEGORY_FOUND_WITH_ID);
            } else if (!entityCategoryDataFromDB.isModifiable()) {
                logger.error("Entity category cannot be modified");
                throw new InvalidEntityCategoryException(ErrorMessages.CANNOT_UPDATE_ENTITY_CATEGORY);
            }

            checkEntityCategoryNameForUpdate(entityCategory.getName(), entityCategoryDataFromDB.getName(), EntityCategoryData.class);
        }
    }

    /**
     * @param givenName
     * @param actualName
     * @param entityCategoryDataClass
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             when entity category already exists in the database.
     * 
     * @throws PKIConfigurationServiceException
     *             if any exception arises when fetching entity categories from database
     */
    private void checkEntityCategoryNameForUpdate(final String givenName, final String actualName, final Class<EntityCategoryData> entityCategoryDataClass)
            throws EntityCategoryAlreadyExistsException, PKIConfigurationServiceException {
        if (!actualName.equals(givenName)) {
            checkEntityCategoryNameAvailability(givenName, entityCategoryDataClass);
        }

    }

    /**
     * @param entityCategory
     * @param operationType
     * @param entityCategoryDataClass
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             when entity category already exists in the database.
     * 
     * @throws InvalidEntityCategoryException
     *             Thrown in case of category name format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             if any exception arises when fetching entity categories from database
     */
    private void validateEntityCategoryNameFormat(final EntityCategory entityCategory, final OperationType operationType, final Class<EntityCategoryData> entityCategoryDataClass)
            throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {
        logger.info("Validating entity category name {}", entityCategory);

        entityCategory.setName(entityCategory.getName().trim());
        checkEntityCategoryNameFormat(entityCategory.getName());

        if (operationType.equals(OperationType.CREATE)) {
            checkEntityCategoryNameAvailability(entityCategory.getName(), entityCategoryDataClass);
        }
    }

    /**
     * @param categoryName
     * @param entityCategoryDataClass
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             when entity category already exists in the database.
     * 
     * @throws PKIConfigurationServiceException
     *             if any exception arises when fetching entity categories from database *
     */
    private void checkEntityCategoryNameAvailability(final String categoryName, final Class<EntityCategoryData> entityCategoryDataClass) throws EntityCategoryAlreadyExistsException,
            PKIConfigurationServiceException {
        try {
            if (!(persistenceManager.findEntityByName(entityCategoryDataClass, categoryName, NAME_PATH) == null)) {
                final String entitydata = entityCategoryDataClass.getAnnotation(Table.class).name();
                logger.error("{} with name {} already exists", entitydata, categoryName);
                throw new EntityCategoryAlreadyExistsException(entityCategoryDataClass.getAnnotation(Table.class).name() + " with name " + categoryName + " already exists");
            }
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error while checking database if name " + categoryName + " exists in " + entityCategoryDataClass.getAnnotation(Table.class).name());
            throw new PKIConfigurationServiceException("Error while checking database if name " + categoryName + " exists in " + entityCategoryDataClass.getAnnotation(Table.class).name(), persistenceException);
        }

    }

    /**
     * @param categoryName
     * 
     * @return InvalidEntityCategoryException thrown when the give entity category name is not in the correct format.
     */
    private void checkEntityCategoryNameFormat(final String categoryName) throws InvalidEntityCategoryException {
        if (!ValidationUtils.validatePattern(NAME_REGEX, categoryName)) {
            logger.debug("{} {}", ErrorMessages.INVALID_NAME_FORMAT, categoryName);
            throw new InvalidEntityCategoryException(ErrorMessages.INVALID_NAME_FORMAT + " " + categoryName);
        }

    }

    /**
     * This method is used to validate the Entity Category during the update Category operation.
     * 
     * @param entityCategory
     *            entity category object for update
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
    public void validateUpdate(final EntityCategory category) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {

        validateEntityCategory(category, OperationType.UPDATE);
    }

}
