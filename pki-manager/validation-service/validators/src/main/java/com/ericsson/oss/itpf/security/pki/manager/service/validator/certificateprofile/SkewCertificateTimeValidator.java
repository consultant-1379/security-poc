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

package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile;

import javax.inject.Inject;
import javax.xml.datatype.Duration;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class validates Certificate Profile Skew Certificate Time for a {@link CertificateProfile}
 */
public class SkewCertificateTimeValidator implements CommonValidator<CertificateProfile> {

    @Inject
    Logger logger;
    private static final String VALIDITY_PATTERN = "^P([0-9]*Y)?([0-9]*M)?([0-9]*D)?T?([0-9]*H)?([0-9]*M)?([0-9]*S)?$";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateSkewCertificateTime(certificateProfile);

    }

    private void validateSkewCertificateTime(final CertificateProfile certificateProfile) throws InvalidProfileAttributeException {

        final Duration skewCertificateTime = certificateProfile.getSkewCertificateTime();
        logger.debug("Validating SkewCertificateTime in CertificateProfile {} ", skewCertificateTime);

        if (skewCertificateTime == null) {
            return;
        }

        final Duration certificateValidity = certificateProfile.getCertificateValidity();

        if (!skewCertificateTime.isShorterThan(certificateValidity)) {
            logger.error("SkewCertificateTime is longer than Certificate validity {}", skewCertificateTime);
            throw new InvalidProfileAttributeException("Invalid Skew Time");
        }

        final String skewCertificateDuration = skewCertificateTime.toString();

        if (!ValidationUtils.validatePattern(VALIDITY_PATTERN, skewCertificateDuration)) {
            logger.error("Invalid Skew Time {} ", skewCertificateDuration);
            throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.ERR_INVALID_SKEW_TIME_FORMAT + skewCertificateDuration);
        }

    }
}
