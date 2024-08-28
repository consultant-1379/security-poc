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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;

/**
 * This class validates subjectAltName present in {@link EntityProfile}.
 *
 * @author tcsvmeg
 *
 */
public class EPSubjectAltNameValidator {

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Inject
    SubjectAltNameValidator subjectAltNameValidator;

    @Inject
    CommonProfileHelper commonProfileHelper;

    @Inject
    Logger logger;

    /**
     *
     * @param entityProfile
     *            entityprofile object
     * @return boolean returns whether the subjectAltName is valid or not.
     * @throws InvalidSubjectAltNameExtension
     *             thrown when given subject alt name is not valid.
     */
    public boolean validate(final EntityProfile entityProfile) throws CertificateExtensionException, InvalidSubjectAltNameExtension, ProfileServiceException, ProfileNotFoundException {

        final String certificateProfileName = entityProfile.getCertificateProfile().getName();
        final CertificateProfile certificateProfile = commonProfileHelper.getCertificateProfile(certificateProfileName);

        final List<CertificateExtension> certificateExtensions = commonProfileHelper.extractCertificateExtensions(certificateProfile);

        return isValidSubjectAltName(entityProfile.getSubjectAltNameExtension(), certificateExtensions);
    }

    private boolean isValidSubjectAltName(final SubjectAltName subjectAltNameValues, final List<CertificateExtension> certificateExtensions) throws InvalidSubjectAltNameExtension {
        logger.debug("validating SubjectAltName field in entity profile");

        if (subjectAltNameValues == null) {
            return false;
        }

        if (ValidationUtils.isNullOrEmpty(subjectAltNameValues.getSubjectAltNameFields())) {
            return false;
        }

        final SubjectAltName subjectAltName = getSubjectAltName(certificateExtensions);
        final List<SubjectAltNameField> subjectAltNameFields = subjectAltName.getSubjectAltNameFields();
        final List<SubjectAltNameFieldType> supportedSubjectAltNameFieldTypes = new ArrayList<SubjectAltNameFieldType>();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
            supportedSubjectAltNameFieldTypes.add(subjectAltNameField.getType());
        }

        validateSubjectAltNameValues(subjectAltNameValues, supportedSubjectAltNameFieldTypes);

        return true;
    }

    private SubjectAltName getSubjectAltName(final List<CertificateExtension> certificateExtensions) throws InvalidSubjectAltNameExtension {
        SubjectAltName subjectAltName = null;

        for (final CertificateExtension certificateExtension : certificateExtensions) {
            if (certificateExtension instanceof SubjectAltName) {
                subjectAltName = (SubjectAltName) certificateExtension;
            }
        }

        if (subjectAltName == null || ValidationUtils.isNullOrEmpty(subjectAltName.getSubjectAltNameFields())) {
            logger.error("Given SubjectAltName Values are not present in Certificate Profile Extensions");
            throw new InvalidSubjectAltNameExtension(ProfileServiceErrorCodes.ERR_NO_SUBJECT_ALT_NAME_VALUES_IN_DB);
        }

        return subjectAltName;
    }

    private void validateSubjectAltNameValues(final SubjectAltName subjectAltNameValues, final List<SubjectAltNameFieldType> supportedSubjectAltNameFields) throws InvalidSubjectAltNameExtension {
        final List<SubjectAltNameField> entitySubjectAltNameFields = subjectAltNameValues.getSubjectAltNameFields();

        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFields) {
            if (!supportedSubjectAltNameFields.contains(subjectAltNameFields.getType())) {
                logger.error("SubjectAltNameType::", subjectAltNameFields.getType(), " is not present in CertificateExtension attributes");
                throw new InvalidSubjectAltNameExtension(subjectAltNameFields.getType() + " is not present in CertificateExtension attributes");
            }

            subjectAltNameValidator.validate(subjectAltNameFields);
        }
    }
}