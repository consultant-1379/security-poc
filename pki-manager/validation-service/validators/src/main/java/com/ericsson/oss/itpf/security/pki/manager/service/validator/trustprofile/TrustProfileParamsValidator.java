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
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class is used to validate the trust profile parameters.
 */
public class TrustProfileParamsValidator implements CommonValidator<TrustProfile> {

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final TrustProfile trustProfile) throws ValidationException {

        validateProfileFields(trustProfile);
    }

    /**
     * 
     * @param trustProfile
     *            trust profile object
     * @throws MissingMandatoryFieldException
     *             thrown when mandatory fields are empty.
     */
    private void validateProfileFields(final TrustProfile trustProfile) throws MissingMandatoryFieldException {

        if (trustProfile.getTrustCAChains().isEmpty() && trustProfile.getExternalCAs().isEmpty()) {
            logger.info("Validation error : internalCA and externalCA are empty");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_REQUIRED_ATLEAST_ONE_CA);
        }
    }

}
