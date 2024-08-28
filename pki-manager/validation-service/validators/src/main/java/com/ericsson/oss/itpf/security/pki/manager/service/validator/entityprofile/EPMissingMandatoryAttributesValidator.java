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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class consists of common validation between subject and subjectAltName present in {@link EntityProfile}.
 * 
 * @author tcsvmeg
 * 
 */
public class EPMissingMandatoryAttributesValidator implements CommonValidator<EntityProfile> {

    @Inject
    EPSubjectValidator entityProfileSubjectValidator;

    @Inject
    EPSubjectAltNameValidator entityProfileSubjectAltNameValidator;

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateMandatoryAttributes(entityProfile);
    }

    private void validateMandatoryAttributes(final EntityProfile entityProfile) throws MissingMandatoryFieldException {

        if (entityProfile.getSubject() == null || ValidationUtils.isNullOrEmpty(entityProfile.getSubject().getSubjectFields())) {
            if (entityProfile.getCertificateProfile().isForCAEntity()) {
                logger.error("Subject is mandatory for CA entity");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_REQUIRED_SUBJECT_FOR_CA);
            } else if (entityProfile.getSubjectAltNameExtension() == null || ValidationUtils.isNullOrEmpty(entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields())) {
                logger.error("Subject and SubjectAltName Values are invalid in entityProfile. Either subject or subject Alt name must be defined for entity profile");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_NO_SUBJECT_OR_SUBJECTALTNAME_PRESENT);
            }
        }
    }
}
