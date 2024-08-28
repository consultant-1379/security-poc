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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

/**
 * This class validates certificate extensions provided as part Certificate Profile create/update request
 */

public class CertificateExtensionsValidator {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionValidatorFactory certificateExtensionValidatorFactory;

    /**
     * This method validates the certificate extensions provided as part of certificate profile create/update request
     *
     * @param certificateProfile
     *            certificate profile object received as part of create/update request
     * @throws ProfileServiceException
     * @throws CertificateExtensionException
     * @throws MissingMandatoryFieldException
     * @throws InternalServiceException
     *             if any exception arises when fetching algorithms from database
     */
    public void validate(final CertificateProfile certificateProfile) throws ProfileServiceException, CertificateExtensionException, MissingMandatoryFieldException {
        validateCertificateExtensions(certificateProfile);
    }

    private void validateCertificateExtensions(final CertificateProfile certificateProfile) throws ProfileServiceException, CertificateExtensionException, MissingMandatoryFieldException {
        String issuerName = null;
        final CertificateExtensions certificateExtensions = certificateProfile.getCertificateExtensions();
        final CAEntity issuer = certificateProfile.getIssuer();
        final boolean isProfileForCAEntity = certificateProfile.isForCAEntity();

        if (issuer != null && issuer.getCertificateAuthority() != null && !ValidationUtils.isNullOrEmpty(issuer.getCertificateAuthority().getName())) {
            issuerName = issuer.getCertificateAuthority().getName();
        }

        if (certificateExtensions == null || ValidationUtils.isNullOrEmpty(certificateExtensions.getCertificateExtensions())) {
            throw new CertificateExtensionException(ProfileServiceErrorCodes.REQUIRED_CERTIFICATE_EXTENSIONS);
        }

        final List<CertificateExtension> certificateExtensionsList = certificateExtensions.getCertificateExtensions();
        validateCertificateExtensionList(certificateExtensionsList, issuerName, isProfileForCAEntity);
    }

    private void validateCertificateExtensionList(final List<CertificateExtension> certificateExtensions, final String issuerName, final boolean isProfileForCAEntity) throws ProfileServiceException,
            CertificateExtensionException, MissingMandatoryFieldException {
        final List<CertificateExtensionType> certificateExtensionTypes = new ArrayList<CertificateExtensionType>();

        for (final CertificateExtension certificateExtension : certificateExtensions) {

            if (certificateExtension != null) {

                final CertificateExtensionType certificateExtensionType = CertificateExtensionType.getCertificateExtensionType(certificateExtension.getClass().getSimpleName());

                certificateExtensionTypes.add(certificateExtensionType);
                validateCertificateExtension(certificateExtensionType, certificateExtension, issuerName, isProfileForCAEntity);

            }

        }

        checkIfExtensionsDefined(certificateExtensionTypes, isProfileForCAEntity);
    }

    private void validateCertificateExtension(final CertificateExtensionType certificateExtensionType, final CertificateExtension certificateExtension, final String issuerName,
            final boolean isProfileForCAEntity) throws ProfileServiceException, CertificateExtensionException, MissingMandatoryFieldException {

        final CertificateExtensionValidator certificateExtensionValidator = certificateExtensionValidatorFactory.getCertificateExtensionValidator(certificateExtensionType);

        certificateExtensionValidator.validate(certificateExtension, isProfileForCAEntity, issuerName);

    }

    private void checkIfExtensionsDefined(final List<CertificateExtensionType> certificateExtensionTypes, final boolean isProfileForCAEntity) throws MissingMandatoryFieldException {

        if (isProfileForCAEntity) {

            if (!certificateExtensionTypes.contains(CertificateExtensionType.BASIC_CONSTRAINTS)) {
                logger.error("For CA, BasicConstraints must be specified!");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_BASIC_CONSTRAINTS);
            }

            if (!certificateExtensionTypes.contains(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER)) {
                logger.error("For CA, SubjectKeyIdentifier must be specified!");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_SUBJECT_KEY_IDENTIFIER);
            }

            if (!certificateExtensionTypes.contains(CertificateExtensionType.KEY_USAGE)) {
                logger.error("For CA, KeyUsage must be specified!");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_KEY_USAGE);
            }
        }
    }
}