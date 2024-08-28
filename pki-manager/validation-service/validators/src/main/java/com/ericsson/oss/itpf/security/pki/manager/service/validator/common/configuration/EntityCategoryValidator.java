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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;

/**
 * This class is used to validate entitycategory in entity profile.
 * 
 * @author tcsvmeg
 * 
 */
public class EntityCategoryValidator {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    /**
     * @param category
     * @throws EntityCategoryNotFoundException
     * @throws ProfileServiceException
     */
    public void validate(final EntityCategory category) throws EntityCategoryNotFoundException, ProfileServiceException {

        if (category == null || ValidationUtils.isNullOrEmpty(category.getName())) {
            logger.error("Entity category name cannot be null in entity profile!");
            throw new EntityCategoryNotFoundException(ProfileServiceErrorCodes.ERR_NO_ENTITYCATEGORY_FOUND);
        }

        final EntityCategoryData entityCategoryData = getEntityCategoryDataByName(category.getName());

        if (entityCategoryData == null) {
            logger.error("Invalid entity category found in entity profile!");
            throw new InvalidEntityCategoryException(ProfileServiceErrorCodes.ERR_INVALID_ENTITYCATEGORY_FOUND);
        }
    }

    /**
     * 
     * @param entityCategoryName
     * @return EntityCategoryData returns the entityCategory object containing entitycategory information.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occurs.
     */
    private EntityCategoryData getEntityCategoryDataByName(final String entityCategoryName) throws ProfileServiceException {
        EntityCategoryData entityCategoryData = null;

        try {
            entityCategoryData = persistenceManager.findEntityByName(EntityCategoryData.class, entityCategoryName, Constants.NAME_PATH);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error when fetching entity category with ", entityCategoryName, persistenceException);
            logger.error("Error when fetching entity category with ", entityCategoryName);
            throw new ProfileServiceException(Constants.OCCURED_IN_VALIDATING + Constants.ENTITY_CATEGORY);
        }

        return entityCategoryData;
    }
}
