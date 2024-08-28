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

import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

/**
 * This class validates subjectAltName and subjectAltNameFieldTypes which are present for a {@link Entity}
 *
 * @author xtelsow
 */
public class EntitySubjectAndSANValidator extends AbstractEntityValidator implements CommonValidator<Entity> {

    @Inject
    Logger logger;

    @Inject
    SubjectValidator subjectValidator;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {
        ValidateEntitySubjectAndSAN(entity);
    }

    /**
     * This Method validates the Subject and SubjectAltName of entity i.e {@link Entity}
     *
     * @param entity
     *
     */
    private void ValidateEntitySubjectAndSAN(final Entity entity) throws EntityServiceException, ProfileNotFoundException {
        logger.debug("Validating EntitySubjAndSAN for Entity {}", entity.getEntityInfo().getName());

        final EntityProfileData entityProfileData = getEntityProfileFromDB(entity.getEntityProfile().getName().trim());

        validateSubjectAndSAN(entity.getEntityInfo().getSubject(), entity.getEntityInfo().getSubjectAltName(), entityProfileData);

        logger.debug("Completed Validating EntitySubjAndSAN for Entity {}", entity.getEntityInfo().getName());
    }

    /**
     * This method validates subject and subjectAltName of entityinfo
     *
     * @param subject
     *            subject name from entityinfo
     * @param subjectAltName
     *            subjectAltName from entityinfo
     * @param entityProfileData
     *            entityProfileData which is fetched from database using entityprofile name
     */
    private void validateSubjectAndSAN(final Subject subject, final SubjectAltName subjectAltName, final EntityProfileData entityProfileData) {

        if (subject != null) {
            validateEntitySubject(subject, entityProfileData);
        }

        if (subjectAltName != null) {
            validateSubjectAltName(subjectAltName, entityProfileData);
        }
    }

    /**
     * This method checks whether subjectFieldValue and subjectFieldType of subjectFields from subject object contains valid values
     *
     * @param subject
     *            subject name from entityinfo
     * @param entityProfileData
     *            entityProfileData which is fetched from database using entityprofile name
     * @throws ProfileNotFoundException
     * @throws EntityServiceException
     */
    private <T extends AbstractEntity> void validateEntitySubject(final Subject subject, final EntityProfileData entityProfileData) throws ProfileNotFoundException, EntityServiceException {
        logger.debug("Validating Subject {}", subject);

        Set<SubjectFieldType> subjectFieldTypeDBEntries = null;
        final List<SubjectField> subjectFields = subject.getSubjectFields();

        if (ValidationUtils.isNullOrEmpty(subjectFields)) {
            return;
        }

        subjectFieldTypeDBEntries = getSubjectFieldTypes(entityProfileData);

        logger.debug("entity subject fields {}", subjectFieldTypeDBEntries);

        for (final SubjectField subjectField : subjectFields) {

            String subjectFieldValue = subjectField.getValue();

            if (subjectFieldValue != null) {
                subjectFieldValue = subjectFieldValue.trim();
                if (Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue()) && subjectFieldValue.matches(Constants.UNSUPPORTED_DIRECTORY_STRING_REGEX)) {
                    logger.info("Subject field value {} contains unsupported character (=/\"\\)",subjectFieldValue);
                    throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_FOR_DIRECTORY_STRING_SUBJECT);
                }
                else if (!Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue()) && subjectFieldValue.matches(Constants.UNSUPPORTED_CHAR_REGEX)) {
                    logger.info("Subject field value {} contains unsupported character (=/,\"\\)",subjectFieldValue);
                    throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_SUBJECT);
                }
            } else {
                continue;
            }
            final SubjectFieldType subjectFieldType = subjectField.getType();

            if (!subjectFieldTypeDBEntries.contains(subjectFieldType)) {
                logger.error("unknown Subject Field::", subjectField);
                throw new InvalidSubjectException(subjectField + "is not present in Entity Profile ");
            } else if (subjectFieldValue.equals(OVERRIDING_OPERATOR)) {
                continue;
            } else {
                subjectValidator.validateSubjectValue(subjectFieldType, subjectFieldValue);
            }
        }
    }

    /**
     * This method calls the {@link EntitiesPersistenceHandlerFactory} to get the appropriate {@link EntitiesPersistenceHandler} instance ( {@link EntityPersistenceHandler} ).
     *
     * @return instance of {@link EntitiesPersistenceHandler} ( {@link EntityPersistenceHandler} ).
     *
     */
    @Override
    protected EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler() {
        return entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY);
    }

}
