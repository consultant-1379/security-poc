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

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionsValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;

/**
 * This class validates the Certificate Extensions for a {@link CertificateProfile}
 */
public class CertificateProfileExtensionsValidator implements CommonValidator<CertificateProfile> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionsValidator certificateExtensionsValidator;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateCertificateExtensions(certificateProfile);

    }

    private void validateCertificateExtensions(final CertificateProfile certificateProfile) throws CertificateExtensionException, MissingMandatoryFieldException, ProfileServiceException {
        logger.debug("Validating CertificateExtensions in Certificate Profile {} ", certificateProfile.getCertificateExtensions());

        certificateExtensionsValidator.validate(certificateProfile);
    }

}
