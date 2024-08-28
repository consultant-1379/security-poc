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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

/**
 * This class validates subject present in {@link EntityProfile}.
 *
 * @author tcsvmeg
 *
 */
public class EPSubjectValidator {

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Inject
    SubjectValidator subjectValidator;

    @Inject
    CommonProfileHelper commonProfileHelper;

    @Inject
    Logger logger;

    /**
     *
     * @param entityProfile
     *            entityprofile object
     * @return boolean whether the subject is valid or not.
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory field is missed.
     * @throws InvalidSubjectException
     *             thrown when subject is invalid.
     */
    public boolean validate(final EntityProfile entityProfile) throws MissingMandatoryFieldException, InvalidSubjectException, ProfileServiceException, ProfileNotFoundException {

        final String certificateProfileName = entityProfile.getCertificateProfile().getName();
        final CertificateProfile certificateProfile = commonProfileHelper.getCertificateProfile(certificateProfileName);

        final boolean isCAEntity = certificateProfile.isForCAEntity();
        final Subject subjectCapabilities = certificateProfile.getSubjectCapabilities();

        return isValidSubject(entityProfile.getSubject(), isCAEntity, subjectCapabilities);
    }

    private boolean isValidSubject(final Subject subject, final boolean isCAEntity, final Subject subjectCapabilities) throws InvalidSubjectException {
        logger.debug("validating Subject field in entity profile {}", subject);

        if (subject == null || ValidationUtils.isNullOrEmpty(subject.getSubjectFields())) {
            if (isCAEntity) {
                logger.error("Subject cannot be null for entity profile of CAEntity");
                throw new InvalidSubjectException(ProfileServiceErrorCodes.ERR_REQUIRED_SUBJECT_FOR_CA);
            }
            return false;
        }

        final List<SubjectField> subjectFields = subject.getSubjectFields();
        final List<SubjectField> supportedSubjectFields = subjectCapabilities.getSubjectFields();
        final List<SubjectFieldType> supportedSubjectFieldTypes = new ArrayList<SubjectFieldType>();

        for (final SubjectField subjectField : supportedSubjectFields) {
            supportedSubjectFieldTypes.add(subjectField.getType());
        }

        validateSubjectFields(subjectFields, supportedSubjectFieldTypes);

        return subjectValidator.validate(subject);
    }

    private void validateSubjectFields(final List<SubjectField> subjectFields, final List<SubjectFieldType> supportedSubjectFieldTypes) throws InvalidSubjectException {
        final List<SubjectField> entityProfileSubjectFields = subjectFields;

        for (final SubjectField subjectField : entityProfileSubjectFields) {
            if (!supportedSubjectFieldTypes.contains(subjectField.getType())) {
                logger.error("SubjectFieldType::", subjectField.getType(), " is not present in Subject Capabilities of Certificate profile");
                throw new InvalidSubjectException(subjectField.getType() + " is not present in Subject Capabilities of Certificate profile");
            }
        }
    }
}