/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;

/**
 * This class is used to check whether mandatory parameters are present for a {@link Entity}
 *
 * @author xtelsow
 */
public class EntityMissingMandatoryAttributesValidator implements CommonValidator<Entity> {
    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws MissingMandatoryFieldException, ValidationException {
        logger.debug("Validating Mandatory params for Entity {}", entity.getEntityInfo().getName());

        validateMandatoryAttributes(entity);

        logger.debug("Completed Validating Mandatory params for Entity {}", entity.getEntityInfo().getName());

    }

    /**
     * @param entity
     *
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     */
    private void validateMandatoryAttributes(final Entity entity) throws MissingMandatoryFieldException {
        if (entity.getEntityInfo() == null) {
            logger.error("Entity Info cannot be null");
            throw new MissingMandatoryFieldException("Entity Info cannot be null");
        }
        if (entity.getEntityInfo().getName() == null) {
            logger.error("Name cannot be null");
            throw new MissingMandatoryFieldException("Name cannot be null");
        }

        final String trimmedName = entity.getEntityInfo().getName().trim();

        if (trimmedName.isEmpty()) {
            logger.error("Name cannot be null");
            throw new MissingMandatoryFieldException("Name cannot be empty");
        }

        entity.getEntityInfo().setName(trimmedName);

        if (!isSubjectValid(entity.getEntityInfo().getSubject()) && !isSANValid(entity.getEntityInfo().getSubjectAltName())) {
            logger.error("Subject or Subject Alternative Name is mandatory.");
            throw new MissingMandatoryFieldException("Subject or Subject Alternative Name is mandatory.");
        }

    }

    /**
     * This method checks whether the subject name is null and subjectfields are empty or not.
     *
     * @param subject
     *            subject name from entityinfo
     * @return boolean value either true or false
     */
    private boolean isSubjectValid(final Subject subject) {

        if (subject == null) {
            return false;
        }
        return !ValidationUtils.isNullOrEmpty(subject.getSubjectFields());
    }

    /**
     * This method checks whether the subjectAltName is null and subjectAltNameFields are empty or not.
     *
     * @param subjectAltName
     *            subjectAltName from entityinfo
     * @return boolean value either true or false
     */
    private boolean isSANValid(final SubjectAltName subjectAltName) {

        if (subjectAltName == null) {
            return false;
        }
        return !ValidationUtils.isNullOrEmpty(subjectAltName.getSubjectAltNameFields());
    }

}
