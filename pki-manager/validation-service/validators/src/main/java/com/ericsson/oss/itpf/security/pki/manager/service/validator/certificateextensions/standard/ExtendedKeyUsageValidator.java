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

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;

/**
 * This class validates ExtendedKeyUsage extension. Critical can be marked true or false.
 * <p>
 * If extended KeyUsage type given,at least 1 keyPurposeID must be specified. If AnyExtendedKeyUsage purposeID present, critical must be true for this extension.
 * </p>
 * 
 */
@CertificateExtensionsQualifier(CertificateExtensionType.EXTENDED_KEY_USAGE)
public class ExtendedKeyUsageValidator extends StandardExtensionValidator {

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws MissingMandatoryFieldException,
            InvalidExtendedKeyUsageExtension {
        validateExtendedKeyUsage((ExtendedKeyUsage) certificateExtension);
    }

    /**
     * @param extendedKeyUsage
     */
    private void validateExtendedKeyUsage(final ExtendedKeyUsage extendedKeyUsage) throws MissingMandatoryFieldException, InvalidExtendedKeyUsageExtension {
        logger.debug("Validating ExtendedKeyUsage in CertificateProfile{}", extendedKeyUsage);

        if (extendedKeyUsage == null) {
            return;
        }

        final List<KeyPurposeId> keyPurposeIds = extendedKeyUsage.getSupportedKeyPurposeIds();

        if (ValidationUtils.isNullOrEmpty(keyPurposeIds)) {
            logger.error("Atleast 1 keyPurposeID must be specified!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.INVALID_KEY_PURPOSE_ID);
        }

        if (keyPurposeIds.contains(KeyPurposeId.ANY_EXTENDED_KEY_USAGE) && extendedKeyUsage.isCritical()) {
            logger.error("If AnyExtendedKeyUsage purposeID present, critical must be false!");
            throw new InvalidExtendedKeyUsageExtension(ProfileServiceErrorCodes.ANY_EXTENDED_KEY_USAGE_PRESENT + ProfileServiceErrorCodes.CRITICAL_MUST_BE_FALSE);
        }

    }
}
