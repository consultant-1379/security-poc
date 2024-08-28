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
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

//TORF-101804 : Changed validation that issuerUniqueIdentifier must be false
/**
 * This class validates CertificateProfile Issuer UniqueIdentifier for a {@link CertificateProfile}
 */
public class IssuerUniqueIdentifierValidator implements CommonValidator<CertificateProfile> {
    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateIssuerUniqueIdentifier(certificateProfile.isIssuerUniqueIdentifier(), certificateProfile.getVersion());
    }

    private void validateIssuerUniqueIdentifier(final boolean issuerUniqueIdentifier, final CertificateVersion certificateVersion) throws InvalidProfileAttributeException {
        logger.debug("Validating IssuerUniqueIdentifier in Certificate Profile {} ", issuerUniqueIdentifier);

        if (!isFieldNotAvailableForProfileV3(certificateVersion, issuerUniqueIdentifier)) {
            logger.error("For Version V3, IssuerUniqueIdentifier must be false {} ", issuerUniqueIdentifier);
            throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.ERR_INVALID_ISSUER_UNIQUE_IDENTIFIER);

        }
    }

    private boolean isFieldNotAvailableForProfileV3(final CertificateVersion certificateVersion, final boolean isIdentifierAvailable) {
        if (certificateVersion == CertificateVersion.V3 && isIdentifierAvailable) {
            return false;
        }
        return true;
    }
}
