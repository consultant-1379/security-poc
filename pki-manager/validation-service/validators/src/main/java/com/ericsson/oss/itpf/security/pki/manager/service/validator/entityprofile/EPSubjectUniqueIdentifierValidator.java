/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;

/**
 * This class validates subject unique identifier provided in {@link EntityProfile}.
 *
 * @author zkakven
 *
 */

public class EPSubjectUniqueIdentifierValidator implements CommonValidator<EntityProfile> {

    @Inject
    Logger logger;

    @Inject
    CommonProfileHelper commonProfileHelper;

    /**
     *
     * @param entityProfile
     *            entityProfile object
     * @throws InvalidProfileAttributeException
     *             thrown when subject unique identifier in certificate profile is set to false.
     */

    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateSubjectUniqueIdentifier(entityProfile);
    }

    private void validateSubjectUniqueIdentifier(final EntityProfile entityProfile)
            throws InvalidProfileAttributeException {

        final String certificateProfileName = entityProfile.getCertificateProfile().getName();
        final CertificateProfile certificateProfile = commonProfileHelper.getCertificateProfile(certificateProfileName);
        final String subjectUniqueIdentifierValue = entityProfile.getSubjectUniqueIdentifierValue();

        if (subjectUniqueIdentifierValue != null && subjectUniqueIdentifierValue.matches(Constants.UNSUPPORTED_CHAR_REGEX)) {
            logger.error("Subject unique identifier value {} contains unsupported character", subjectUniqueIdentifierValue);
            throw new InvalidProfileAttributeException(ErrorMessages.UNSUPPORTED_SUID_EP_CHARACTERS_ERROR);
        }
        if (!certificateProfile.isSubjectUniqueIdentifier() && entityProfile.getSubjectUniqueIdentifierValue() != null) {
            logger.error(ErrorMessages.UNACCEPTED_SUID_ENTITY_PROFILE_VALUE_ERROR);
            throw new InvalidProfileAttributeException(ErrorMessages.UNACCEPTED_SUID_ENTITY_PROFILE_VALUE_ERROR);
        }
    }
}
