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

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;

/**
 * This class validates CertificateProfile version
 */
public class CertificateVersionValidator implements CommonValidator<CertificateProfile> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateVersion(certificateProfile.getVersion());

    }

    private void validateVersion(final CertificateVersion certificateVersion) throws UnSupportedCertificateVersion {
        logger.debug("Validating Version in Certificate Profile {} ", certificateVersion);

        if (!(certificateVersion == CertificateVersion.V3)) {
            logger.error("Invalid Version {} Only V3 is supported for now ", certificateVersion);
            throw new UnSupportedCertificateVersion(ProfileServiceErrorCodes.REQUIRED_VERSION);
        }
    }
}
