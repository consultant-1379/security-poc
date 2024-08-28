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
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class validates the Certificate Duration for a {@link CertificateProfile}
 */
public class CertificateValidityValidator implements CommonValidator<CertificateProfile> {
    @Inject
    Logger logger;

    private static final String VALIDITY_PATTERN = "^(?!P0*Y?0*M?0*D?T?0*H?0*M?([0-9]*S)?$)P([0-9]*Y)?([0-9]*M)?([0-9]*D)?T?([0-9]*H)?([0-9]*M)?([0-9]*S)?$";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateCertificateValidity(certificateProfile);
    }

    private void validateCertificateValidity(final CertificateProfile certificateProfile) throws InvalidProfileAttributeException, MissingMandatoryFieldException {
        final Duration validity = certificateProfile.getCertificateValidity();

        logger.debug("Validating Validity in CertificateProfile {} ", validity);

        if (validity == null) {
            logger.error("Validity must be specified {} ", validity);
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_REQUIRED_VALIDITY);
        }

        final String validityDuration = validity.toString();

        if (!ValidationUtils.validatePattern(VALIDITY_PATTERN, validityDuration)) {
            logger.error("Certificate validity is not valid {} in Certificate profile {}", validityDuration, certificateProfile);
            throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.ERR_INVALID_VALIDITY_FORMAT);
        }

    }

}
