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

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

/**
 * This class Validates Certificate Profile Subject Capabilities for a {@link CertificateProfile}
 */
public class SubjectCapabilitiesValidator implements CommonValidator<CertificateProfile> {
    @Inject
    Logger logger;

    @Inject
    SubjectValidator subjectValidator;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateSubjectCapabilities(certificateProfile.getSubjectCapabilities());
    }

    /**
     * @param subjectCapabilities
     */
    private void validateSubjectCapabilities(final Subject subjectCapabilities) throws InvalidSubjectException, MissingMandatoryFieldException {

        if (subjectCapabilities == null || ValidationUtils.isNullOrEmpty(subjectCapabilities.getSubjectFields())) {
            logger.error("SubjectCapabilties cannot be null .. it must have atleast one subject!");
            throw new InvalidSubjectException(ProfileServiceErrorCodes.ERR_INVALID_SUBJECT_CAPABILITIES);
        }
        final List<SubjectField> subjectFields = subjectCapabilities.getSubjectFields();
        for (final SubjectField subjectField : subjectFields) {
            if (subjectField != null) {
                validateSubjectField(subjectField);
            }
        }
    }

    /**
     * @param subjectField
     */
    private void validateSubjectField(final SubjectField subjectField) throws MissingMandatoryFieldException, InvalidSubjectException {
        final boolean isSubjectFieldTypeValid = validateSubjectFieldType(subjectField);
        if (subjectField.getType() == null || !isSubjectFieldTypeValid) {
            logger.error("For SubjectField in subject capabilities, type must be specified!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_INVALID_SUBJECT_FIELD_TYPE);
        }

        if (subjectField.getValue() != null) {
            logger.error("For SubjectField, value must not be given as part of input!");
            throw new InvalidSubjectException(ProfileServiceErrorCodes.ERR_INVALID_SUBJECT_FIELD_VALUE);
        }
    }

    private boolean validateSubjectFieldType(final SubjectField subjectField){
        for(SubjectFieldType subjectFieldType : SubjectFieldType.values()){
            if(subjectFieldType.equals(subjectField.getType())){
                return true;
            }
        }
        return false;
    }
}
