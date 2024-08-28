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

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.AbstractProfileNameValidator;

/**
 * This class is used to validate name for a {@link EntityProfile} during create operation.
 * 
 * @author tcsvmeg
 * 
 */
public class CreateEntityProfileNameValidator extends AbstractProfileNameValidator implements CommonValidator<EntityProfile> {

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateEntityProfile(entityProfile);
    }


    private void validateEntityProfile(final EntityProfile entityProfile) throws InvalidProfileAttributeException, ProfileServiceException, ProfileAlreadyExistsException {
        logger.debug("Validating  Name in {} {}", entityProfile.getType(), entityProfile.getName());

        entityProfile.setName(entityProfile.getName().trim());
        checkProfileNameFormat(entityProfile.getName());
        checkProfileNameAvailability(entityProfile.getName(), EntityProfileData.class);
    }
}