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

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

public class SubjectAndSubjectAltNameValidator implements CommonValidator<EntityProfile> {

    @Inject
    EPSubjectValidator epSubjectValidator;

    @Inject
    EPSubjectAltNameValidator epSubjectAltNameValidator;

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateSubjectAndSubjectAltName(entityProfile);
    }

    private void validateSubjectAndSubjectAltName(final EntityProfile entityProfile) throws MissingMandatoryFieldException, CertificateExtensionException, InvalidSubjectAltNameExtension,
            InvalidSubjectException, ProfileServiceException, ProfileNotFoundException {

        final boolean isValidSubject = epSubjectValidator.validate(entityProfile);
        final boolean isValidSubjectAltName = epSubjectAltNameValidator.validate(entityProfile);

        if (!isValidSubjectAltName && !isValidSubject) {
            logger.error("Subject and SubjectAltName Values are invalid in entityProfile");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_NO_SUBJECT_OR_SUBJECTALTNAME_PRESENT);
        }
    }
}
