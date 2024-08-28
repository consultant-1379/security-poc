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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

/**
 * This class is used to validate subject name and subjectFieldTypes for a
 * {@link CaEntity}
 *
 * @author xtelsow
 */
public class CaEntitySubjectValidator extends AbstractEntityValidator implements CommonValidator<CAEntity> {

    @Inject
    Logger logger;

    @Inject
    SubjectValidator subjectValidator;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.
     * CommonValidator#validate(java.lang.Object)
     */
    @SuppressWarnings({"squid:S119","squid:S1130"})
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity)
            throws ValidationException {
        validateEntitySubject(caEntity);
    }

    /**
     * This Method validates the EntitySubject of CaEntity i.e {@link CAEntity}
     *
     * @param caEntity
     *
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     *
     */
    @SuppressWarnings("squid:S1130")
    private void validateEntitySubject(final CAEntity caEntity) throws EntityServiceException, InvalidSubjectException,
            MissingMandatoryFieldException, ProfileNotFoundException {
        logger.debug("Validating EntitySubject for CA Entity {}", caEntity.getCertificateAuthority().getName());

        final EntityProfileData entityProfileData = getEntityProfileFromDB(
                caEntity.getEntityProfile().getName().trim());

        validateEntitySubject(caEntity.getCertificateAuthority().getSubject(), entityProfileData);

        logger.debug("Completed Validating EntitySubject for CA Entity {}",
                caEntity.getCertificateAuthority().getName());
    }

    /**
     * This method validates SubjectFields and SubjectFieldTypes present in
     * entityProfileData of caentity
     *
     * @param subject
     *            is the subject name in CertificateAuthority
     * @param entityProfileData
     *            is the entityProfileData for respective entityprofile name in
     *            caentity
     * @throws InvalidSubjectException
     *             is thrown when subjectFieldType is not present in Entity
     *             Profile
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     */
    @SuppressWarnings("squid:S1130")
    private void validateEntitySubject(final Subject subject, final EntityProfileData entityProfileData)
            throws InvalidSubjectException, MissingMandatoryFieldException {
        logger.debug("Validating Subject {}", subject);

        Set<SubjectFieldType> subjectFieldTypeDBEntries = null;
        final List<SubjectField> subjectFields = subject.getSubjectFields();

        if (ValidationUtils.isNullOrEmpty(subjectFields)) {
            throw new MissingMandatoryFieldException("Subject cannot be null or empty in CA Entity.");
        }

        subjectFieldTypeDBEntries = getSubjectFieldTypes(entityProfileData);

        logger.debug("entity subject fields {}", subjectFieldTypeDBEntries);

        for (final SubjectField subjectField : subjectFields) {

            String subjectFieldValue = subjectField.getValue();
            final SubjectFieldType subjectFieldType = subjectField.getType();

            if (!ValidationUtils.isNullOrEmpty(subjectFieldValue)) {
                subjectFieldValue = subjectFieldValue.trim();

                validateSubjectFieldTypeAndMatchRegex(subjectField, subjectFieldValue);

                if (!subjectFieldTypeDBEntries.contains(subjectFieldType)) {
                    logger.error("unknown Subject Field::", subjectFieldType);
                    throw new InvalidSubjectException(subjectFieldType + " is not present in Entity Profile ");
                } else if (subjectFieldValue.equals(OVERRIDING_OPERATOR)) {
                    logger.error("Overriding operator is not allowed in CA Entity for Subject Field::", subjectFieldType);
                    throw new InvalidSubjectException(
                        "Overriding operator is not allowed in CA Entity for Subject Field:" + subjectFieldType);
                } else {
                    subjectValidator.validateSubjectValue(subjectFieldType, subjectFieldValue);
                }
            }
            else {
                logger.error("Subject Field {} is empty.", subjectFieldType);
                throw new InvalidSubjectException(subjectFieldType + " is empty in Subject.");
            }
        }
    }

    @SuppressWarnings("squid:S1130")
    private void validateSubjectFieldTypeAndMatchRegex(SubjectField subjectField, String subjectFieldValue) throws InvalidSubjectException {
        if (Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue())
                && subjectFieldValue.matches(Constants.UNSUPPORTED_DIRECTORY_STRING_REGEX)) {
            logger.info("Subject field value {} contains unsupported character (=/\"\\)", subjectFieldValue);
            throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_FOR_DIRECTORY_STRING_SUBJECT);
        } else if (!Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue()) && subjectFieldValue.matches(Constants.UNSUPPORTED_CHAR_REGEX)) {
            logger.info("Subject field value {} contains unsupported character (=/,\"\\)", subjectFieldValue);
            throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_SUBJECT);
        }
    }

    /**
     * This method calls the {@link EntitiesPersistenceHandlerFactory} to get
     * the appropriate {@link EntitiesPersistenceHandler} instance (
     * {@link CAEntityPersistenceHandler} ).
     *
     * @return instance of {@link EntitiesPersistenceHandler} (
     *         {@link CAEntityPersistenceHandler} ).
     *
     */
    @Override
    protected EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler() {
        return entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY);
    }

}
