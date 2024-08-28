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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;

/**
 * This class validates AuthorityKeyIdentifier extension.
 * <p>
 * AuthorityKeyIdentifier extension is mandatory for both CA and End entities and must not be marked critical.
 * </p>
 * 
 * <p>
 * This extension must have either ByAuthorityCertIssuerAndSerialNumber or ByKeyIdentifier set as true
 * </p>
 * 
 */
@CertificateExtensionsQualifier(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER)
public class AuthorityKeyIdentifierValidator extends StandardExtensionValidator {

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws MissingMandatoryFieldException,
            InvalidAuthorityKeyIdentifierExtension {

        validateAuthorityKeyIdentifier((AuthorityKeyIdentifier) certificateExtension);
    }

    /**
     * @param authorityKeyIdentifier
     */
    private void validateAuthorityKeyIdentifier(final AuthorityKeyIdentifier authorityKeyIdentifier) throws MissingMandatoryFieldException, InvalidAuthorityKeyIdentifierExtension {
        logger.debug("Validating AuthorityKeyIdentifier in CertificateProfile{}", authorityKeyIdentifier);

        if (isCertificateExtensionDefined(authorityKeyIdentifier)) {

            if (isCertificateExtensionCritical(authorityKeyIdentifier)) {
                logger.error("For AuthorityKeyIdentifier extension, critical must be false! ");
                throw new InvalidAuthorityKeyIdentifierExtension(ProfileServiceErrorCodes.AUTHORITY_KEY_IDENTIFIER + ProfileServiceErrorCodes.CRITICAL_MUST_BE_FALSE);
            }

            if (authorityKeyIdentifier.getIssuerSubjectAndSerialNumber() != null) {
                logger.error("For AuthorityKeyIdentifier extension, getIssuerSubjectAndSerialNumber cannot be given as input!");
                throw new InvalidAuthorityKeyIdentifierExtension(ProfileServiceErrorCodes.AUTHORITY_KEY_IDENTIFIER + ProfileServiceErrorCodes.INVALID_AUTHORITY_KEY_IDENTIFIER);
            }

            if (authorityKeyIdentifier.getSubjectkeyIdentifier() != null) {
                logger.error("For AuthorityKeyIdentifier extension, SubjectkeyIdentifier cannot be given as input!");
                throw new InvalidAuthorityKeyIdentifierExtension(ProfileServiceErrorCodes.AUTHORITY_KEY_IDENTIFIER + ProfileServiceErrorCodes.INVALID_AUTHORITY_KEY_IDENTIFIER);
            }

            if (authorityKeyIdentifier.getType() == null) {
                logger.error("For AuthorityKeyIdentifier extension, authority key identifier type must be specified!");
                throw new InvalidAuthorityKeyIdentifierExtension(ProfileServiceErrorCodes.AUTHORITY_KEY_IDENTIFIER + ProfileServiceErrorCodes.REQUIRED_AUTHORITY_KEY_IDENTIFIER_TYPE);
            }

        }
    }
}
