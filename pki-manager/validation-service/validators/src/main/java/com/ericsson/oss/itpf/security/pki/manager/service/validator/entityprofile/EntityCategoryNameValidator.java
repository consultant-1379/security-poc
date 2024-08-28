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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.EntityCategoryValidator;

/**
 * This class validates entitycategory present in {@link EntityProfile}.
 * 
 * @author tcsvmeg
 * 
 */
public class EntityCategoryNameValidator implements CommonValidator<EntityProfile> {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    EntityCategoryValidator entityCategoryValidator;

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.validation.common.CommonValidator #validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateEntityCategory(entityProfile);
    }
    
    private void validateEntityCategory(final EntityProfile entityProfile) throws EntityCategoryNotFoundException, InvalidEntityCategoryException, ProfileServiceException {
        entityCategoryValidator.validate(entityProfile.getCategory());
    }
}