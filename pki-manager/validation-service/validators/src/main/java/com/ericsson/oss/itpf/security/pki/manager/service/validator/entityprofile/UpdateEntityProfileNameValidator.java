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
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.AbstractProfileNameValidator;

/**
 * This class is used to validate name for a {@link EntityProfile} during update operation.
 * 
 * @author tcsvmeg
 * 
 */
public class UpdateEntityProfileNameValidator extends AbstractProfileNameValidator implements CommonValidator<EntityProfile> {

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateProfileName(entityProfile);
    }

    private void validateProfileName(final EntityProfile entityProfile) throws InvalidProfileAttributeException, ProfileServiceException, ProfileAlreadyExistsException {
        entityProfile.setName(entityProfile.getName().trim());
        checkProfileNameFormat(entityProfile.getName());

        AbstractProfileData abstractProfileData = null;

        try {
            abstractProfileData = persistenceManager.findEntity(EntityProfileData.class, entityProfile.getId());
        } catch (final PersistenceException persistenceException) {
            logger.error("No profile found..error in Checking DB!");
            throw new ProfileServiceException(ProfileServiceErrorCodes.ERR_NO_PROFILE_FOUND_WITH_ID, persistenceException);
        }

        if (abstractProfileData == null) {
            logger.error("No profile found..error in Checking DB!");
            throw new ProfileServiceException(ProfileServiceErrorCodes.ERR_NO_PROFILE_FOUND_WITH_ID);
        }

        checkProfileNameForUpdate(entityProfile.getName(), abstractProfileData.getName(), EntityProfileData.class);
    }
}