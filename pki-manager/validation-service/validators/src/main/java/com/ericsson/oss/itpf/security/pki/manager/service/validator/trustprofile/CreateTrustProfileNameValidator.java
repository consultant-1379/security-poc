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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.AbstractProfileNameValidator;

/**
 * This class is used to validate name for a {@link TrustProfile} during create operation.
 * 
 * 
 */
public class CreateTrustProfileNameValidator extends AbstractProfileNameValidator implements CommonValidator<TrustProfile> {

    @Inject
    TrustCAChainsValidator trustCAChainsValidator;

    @Inject
    ExternalCAsValidator externalCAsValidator;

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final TrustProfile trustProfile) throws ValidationException {

        validateProfileName(trustProfile);
    }

    /**
     * 
     * @param trustProfile
     *            trustprofile object
     * @throws InvalidProfileAttributeException
     *             thrown when the given profile attribute is invalid.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileAlreadyExistsException
     *             thrown when given profile already exists.
     */
    private void validateProfileName(final TrustProfile trustProfile) throws InvalidProfileAttributeException, ProfileServiceException, ProfileAlreadyExistsException {

        logger.debug("Validating create Trust Profile {}", trustProfile);

        checkProfileNameFormat(trustProfile.getName().trim());
        checkProfileNameAvailability(trustProfile.getName(), TrustProfileData.class);

        logger.debug("Completed validating create Trust Profile", trustProfile);
    }

}
