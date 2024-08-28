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
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.ProfileValidityValidator;

/**
 * This class is used to validate profileValidity for a {@link TrustProfile}.
 * 
 * 
 */
public class TrustProfileValidityValidator implements CommonValidator<TrustProfile> {

    @Inject
    Logger logger;

    @Inject
    ProfileValidityValidator profileValidityValidator;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final TrustProfile trustProfile) throws ValidationException {

        validateProfileValidity(trustProfile);
    }

    /**
     * 
     * @param trustProfile
     *            trust profile object
     * @throws InvalidProfileAttributeException
     *             thrown when the given profile attribute is invalid.
     */
    private void validateProfileValidity(final TrustProfile trustProfile) throws InvalidProfileAttributeException {

        profileValidityValidator.validate(trustProfile.getProfileValidity());
    }

}
