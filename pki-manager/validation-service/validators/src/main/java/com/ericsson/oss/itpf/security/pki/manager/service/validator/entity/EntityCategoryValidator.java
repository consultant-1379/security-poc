/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;

/**
 * This class is used to verify the category parameters of entity i.e. {@link Entity}
 *
 * @author xtelsow
 */
public class EntityCategoryValidator implements CommonValidator<Entity> {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {
        logger.debug("Validating Category params for Entity {}", entity.getCategory().getName());

        validateCategory(entity.getCategory());

        logger.debug("Completed Validating Category params for Entity {}", entity.getCategory().getName());

    }

    /**
     * This Method validates the mandatory params of category object in entity i.e {@link Entity}
     *
     * @param category
     *            is the category object value from entity
     * @throws EntityServiceException
     *             is thrown when internal service exception occurs due to invalid database operations
     * @throws InvalidEntityCategoryException
     *             is thrown when a given category is not found
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     */
    private void validateCategory(final EntityCategory category) throws EntityServiceException, InvalidEntityCategoryException, MissingMandatoryFieldException, PersistenceException {

        if (category == null) {
            logger.error("Category cannot be null");
            throw new MissingMandatoryFieldException("Category cannot be null");
        }
        String categoryName = category.getName();
        if (categoryName != null) {
            categoryName = categoryName.trim();
        }

        if (ValidationUtils.isNullOrEmpty(categoryName)) {
            logger.error("Category name cannot be null");
            throw new MissingMandatoryFieldException("Category name cannot be null");
        }
        EntityCategoryData entityCategoryData = null;
        try {
            entityCategoryData = persistenceManager.findEntityByName(EntityCategoryData.class, categoryName, "name");
        } catch (final PersistenceException persistenceException) {
            throw new EntityServiceException("Internal Service exception", persistenceException);
        }
        if (entityCategoryData == null) {
            logger.error("Given Category not found");
            throw new InvalidEntityCategoryException("Given Category not found");
        }

    }

}
