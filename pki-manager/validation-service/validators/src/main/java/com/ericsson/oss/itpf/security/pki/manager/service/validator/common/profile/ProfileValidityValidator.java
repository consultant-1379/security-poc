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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile;

import java.util.Date;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class is used to validate profile validity. We are not calling this class. No more we are validating the profile validity field.
 * 
 * @author tcsvmeg
 * 
 */
public class ProfileValidityValidator {

    @Inject
    Logger logger;

    /**
     * This method is used to validate the given profile validity
     * 
     * @param givenDate
     *            profile validity value
     * @throws InvalidProfileAttributeException
     *             thrown when the profile has already expired.
     */
    public void validate(final Date givenDate) throws InvalidProfileAttributeException {
        final Date currentDate = new Date();

        if (givenDate != null && givenDate.before(currentDate) && !givenDate.equals(currentDate)) {
            logger.error("Profile has expired already!");
            throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.ERR_INVALID_PROFILE_VALIDITY);
        }

    }
}
