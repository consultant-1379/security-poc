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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class is used to validate name for a {@link CaEntity} during update operation.
 *
 * @author xtelsow
 */
public class UpdateCaEntityNameValidator extends AbstractEntityValidator implements CommonValidator<CAEntity> {

    @Inject
    Logger logger;

    private final static String NAME_PATH = "certificateAuthorityData.name";

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        validateCaEntityName(caEntity);
    }

    /**
     * This Method validates the Name of CaEntity i.e {@link CAEntity}
     *
     * @param caEntity
     * @throws EntityNotFoundException
     *             is thrown when respective entity is not found
     */
    private void validateCaEntityName(final CAEntity caEntity) throws EntityAlreadyExistsException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {

        logger.debug("Validating update CA Entity {}", caEntity.getCertificateAuthority().getName());

        final long id = caEntity.getCertificateAuthority().getId();

        final CAEntityData caEntityData = getEntityDataById(id, CAEntityData.class);

        if (caEntityData == null) {
            logger.error("CA Entity {}{}", ProfileServiceErrorCodes.ERR_NO_ENTITY_FOUND, id);
            throw new EntityNotFoundException("CA Entity " + ProfileServiceErrorCodes.ERR_NO_ENTITY_FOUND + id);
        }

        final String trimmedName = caEntity.getCertificateAuthority().getName().trim();

        caEntity.getCertificateAuthority().setName(trimmedName);

        checkEntityNameFormat(caEntity.getCertificateAuthority().getName());

        checkEntityNameForUpdate(caEntity.getCertificateAuthority().getName(), caEntityData.getCertificateAuthorityData().getName(), CAEntityData.class, NAME_PATH);

        logger.debug("Completed validating update CA Entity", caEntity.getCertificateAuthority().getName());
    }

    /**
     * This method calls the {@link EntitiesPersistenceHandlerFactory} to get the appropriate {@link EntitiesPersistenceHandler} instance ( {@link CAEntityPersistenceHandler} ).
     *
     * @return instance of {@link EntitiesPersistenceHandler} ( {@link CAEntityPersistenceHandler} ).
     *
     */
    @Override
    protected EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler() {
        return entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY);
    }

}
