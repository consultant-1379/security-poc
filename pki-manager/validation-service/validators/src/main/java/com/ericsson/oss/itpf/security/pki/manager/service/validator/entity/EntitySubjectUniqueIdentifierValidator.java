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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class validates subject unique identifier provided in {@link Entity}.
 *
 * @author zkakven
 *
 */

public class EntitySubjectUniqueIdentifierValidator extends AbstractEntityValidator implements CommonValidator<Entity> {

    /**
     *
     * @param entity
     *            entity object
     * @throws InvalidEntityAttributeException
     *             thrown when subject unique identifier in certificate profile is set to false.
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {
        validateSubjectUniqueIdentifier(entity);
    }

    private void validateSubjectUniqueIdentifier(final Entity entity)
            throws InvalidEntityAttributeException {
        final EntityProfileData entityProfileData = getEntityProfileFromDB(entity.getEntityProfile().getName().trim());
        final String subjectUniqueIdentifierValue = entity.getSubjectUniqueIdentifierValue();

        if (subjectUniqueIdentifierValue != null && subjectUniqueIdentifierValue.matches(Constants.UNSUPPORTED_SUID_CHAR_REGEX)) {
            logger.error("Subject unique identifier value {} contains unsupported character", subjectUniqueIdentifierValue);
            throw new InvalidEntityAttributeException(ErrorMessages.UNSUPPORTED_SUID_CHARACTERS_ERROR);
        }

        if (!entityProfileData.getCertificateProfileData().isSubjectUniqueIdentifier() && entity.getSubjectUniqueIdentifierValue() != null) {
            logger.error(ErrorMessages.UNACCEPTED_SUID_ENTITY_VALUE_ERROR);
            throw new InvalidEntityAttributeException(ErrorMessages.UNACCEPTED_SUID_ENTITY_VALUE_ERROR);
        } else if (entityProfileData.getCertificateProfileData().isSubjectUniqueIdentifier()
                && ((entityProfileData.getSubjectUniqueIdentifierValue() != null && entityProfileData.getSubjectUniqueIdentifierValue().equals("?")) && entity.getSubjectUniqueIdentifierValue() == null)) {
            logger.error(ErrorMessages.INVALID_SUID_ENTITY_VALUE_ERROR);
            throw new InvalidEntityAttributeException(ErrorMessages.INVALID_SUID_ENTITY_VALUE_ERROR);
        }
    }

    @Override
    protected EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler() {
        return entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY);
    }
}