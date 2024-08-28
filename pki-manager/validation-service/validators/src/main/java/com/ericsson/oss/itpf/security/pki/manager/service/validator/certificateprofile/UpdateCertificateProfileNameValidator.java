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
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.AbstractProfileNameValidator;

/**
 * This class validates the Certificate Profile Name while updating the certificate for a {@link CertificateProfile}
 */
public class UpdateCertificateProfileNameValidator extends AbstractProfileNameValidator implements CommonValidator<CertificateProfile> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateCertificateProfileName(certificateProfile);

    }

    private void validateCertificateProfileName(final CertificateProfile certificateProfile) throws ProfileNotFoundException, ProfileServiceException, InvalidProfileAttributeException,
            ProfileAlreadyExistsException {
        final CertificateProfileData certificateProfileData = getEntityData(certificateProfile.getId(), CertificateProfileData.class);

        certificateProfile.setName(certificateProfile.getName().trim());
        checkProfileNameFormat(certificateProfile.getName());

        checkProfileNameForUpdate(certificateProfile.getName(), certificateProfileData.getName(), CertificateProfileData.class);
    }
}
