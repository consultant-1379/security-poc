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
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;

/**
 * This class validates SubjectAltName extension.
 * <p>
 * If specified, must contain at least one supported {@link SubjectAltNameFieldType}
 * </p>
 * 
 */
@CertificateExtensionsQualifier(CertificateExtensionType.SUBJECT_ALT_NAME)
public class SubjectAltNameExtensionValidator extends StandardExtensionValidator {

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws MissingMandatoryFieldException,
            InvalidSubjectAltNameExtension {
        validateSubjectAltName((SubjectAltName) certificateExtension);
    }

    /**
     * @param subjectKeyIdentifier
     */
    private void validateSubjectAltName(final SubjectAltName subjectAltName) throws MissingMandatoryFieldException, InvalidSubjectAltNameExtension {
        logger.debug("Validating SubjectAltName in CertificateProfile{}", subjectAltName);

        if (subjectAltName == null) {
            return;
        }

        if (ValidationUtils.isNullOrEmpty(subjectAltName.getSubjectAltNameFields())) {
            logger.error("For SubjectAltName extension, atleast one supported Subject Alt Name field must be specified!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.INVALID_SUBJECT_ALT_NAME);
        }

        final List<SubjectAltNameField> subjectAltNameFields = subjectAltName.getSubjectAltNameFields();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
            if (subjectAltNameField != null) {
                validateSubjectAltNameField(subjectAltNameField);
            }
        }
    }

    /**
     * @param subjectAltNameField
     */
    private void validateSubjectAltNameField(final SubjectAltNameField subjectAltNameField) throws InvalidSubjectAltNameExtension {
        if (subjectAltNameField.getType() == null) {
            logger.error("For SubjectAltNameField, type must be specified!");
            throw new InvalidSubjectAltNameExtension(ProfileServiceErrorCodes.INVALID_SUBJECT_ALT_NAME_FIELD_TYPE);
        }

        if (subjectAltNameField.getValue() != null) {
            logger.error("For SubjectAltNameField, value must not be given as part of input!");
            throw new InvalidSubjectAltNameExtension(ProfileServiceErrorCodes.INVALID_SUBJECT_ALT_NAME_FIELD_VALUE);
        }
    }
}
