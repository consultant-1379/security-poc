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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.privateinternet;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityInformationAccessExtension;

/**
 * This class validates AuthorityInformationAccess extension provided for Certificate Profile creation
 *
 * <p>
 * For this extension , critical must be false for sure. AccessLocation can be null. If given, must be in ldap,http or ftp uri format
 * </p>
 */
@CertificateExtensionsQualifier(CertificateExtensionType.AUTHORITY_INFORMATION_ACCESS)
public class AuthorityInformationAccessValidator extends PrivateInternetExtensionValidator {

    private static final String ACCESS_LOCATION_PATTERN = "^ldap://([a-z]*\\.[a-z]*\\.[a-z]*)?(:\\d{1,5})?\\/((dc=|cn=|ou=|o=|street=|l=|st=|c=|uid=)([a-z]+(\\%?(\\d)*?)?[a-z]*,?))+\\?([a-z]+,?;?)+[a-z()=?]*$|^(http:|ftp:)//([a-z]*\\.[a-z]*\\.[a-z]*)\\/([a-z]*\\/)*(([a-z0-9]+\\.)+(cer|p7c))$";

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws MissingMandatoryFieldException,
            InvalidAuthorityInformationAccessExtension {

        validateAuthorityInformationAccess((AuthorityInformationAccess) certificateExtension);

    }

    private void validateAuthorityInformationAccess(final AuthorityInformationAccess authorityInformationAccess) throws MissingMandatoryFieldException, InvalidAuthorityInformationAccessExtension {
        logger.debug("Validating AuthorityInformationAccess in CertificateProfile{}", authorityInformationAccess);

        if (isCertificateExtensionDefined(authorityInformationAccess)) {

            if (isCertificateExtensionCritical(authorityInformationAccess)) {
                logger.error("For AuthorityInformationAccess extension, critical must be false!");
                throw new InvalidAuthorityInformationAccessExtension(ProfileServiceErrorCodes.AUTHORITY_INFORMATION_ACCESS + ProfileServiceErrorCodes.CRITICAL_MUST_BE_FALSE);
            }

            final List<AccessDescription> accessDescriptionList = authorityInformationAccess.getAccessDescriptions();

            validateAccessDescriptions(accessDescriptionList);
        }
    }

    private void validateAccessDescriptions(final List<AccessDescription> accessDescriptionList) {

        if (!ValidationUtils.isNullOrEmpty(accessDescriptionList)) {
            for (final AccessDescription accessDescription : accessDescriptionList) {
                validateAccessDescription(accessDescription);
            }
        }
    }

    private void validateAccessDescription(final AccessDescription accessDescription) {

        if (accessDescription.getAccessMethod() == null) {
            logger.error("AccessDescriptionList must contain atleast one access method!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.INVALID_ACCESS_DESCRIPTION);
        }

        final String accessLocation = accessDescription.getAccessLocation();

        validateAccessLocation(accessLocation);
    }

    private void validateAccessLocation(final String accessLocation) {

        if (!ValidationUtils.isNullOrEmpty(accessLocation)) {

            if (!ValidationUtils.validatePattern(ACCESS_LOCATION_PATTERN, accessLocation)) {
                logger.error("Invalid AccessLocation given!");
                throw new InvalidAuthorityInformationAccessExtension(ProfileServiceErrorCodes.INVALID_ACCESS_LOCATION);
            }
        }

    }
}
