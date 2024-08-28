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

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class is used to validate name for a {@link Entity} during update operation.
 *
 * @author xtelsow
 */
public class UpdateEntityNameValidator extends AbstractEntityValidator implements CommonValidator<Entity> {

    @Inject
    Logger logger;

    private final static String NAME_PATH = "entityInfoData.name";

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {
        validateEntityName(entity);

    }

    /**
     * This Method validates the name of entity i.e {@link Entity}
     *
     * @param entity
     *
     *
     */
    private void validateEntityName(final Entity entity) throws EntityAlreadyExistsException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        logger.debug("Validating update Entity {}", entity.getEntityInfo().getName());

        final long id = entity.getEntityInfo().getId();

        final EntityData entityData = getEntityDataById(id, EntityData.class);
        if (entityData == null) {
            logger.error(ProfileServiceErrorCodes.ERR_NO_ENTITY_FOUND + " Entity {}" , id);
            throw new EntityNotFoundException("Entity " + ProfileServiceErrorCodes.ERR_NO_ENTITY_FOUND + id);
        }

        checkEntityNameFormat(entity.getEntityInfo().getName());
        checkEntityNameForUpdate(entity.getEntityInfo().getName(), entityData.getEntityInfoData().getName(), EntityData.class, NAME_PATH);

        logger.debug("Completed validating update Entity", entity.getEntityInfo().getName());
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
