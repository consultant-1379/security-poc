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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;

/**
 * Persistence Handler Factory used to get the instance of proper Entity Persistence handler out of {@link CAEntityPersistenceHandler} / {@link EntityPersistenceHandler}
 * 
 */
public class EntitiesPersistenceHandlerFactory {

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    EntitiesPersistenceHandler<CAEntity> cAEntityPersistenceHandler;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntitiesPersistenceHandler<Entity> entityPersistenceHandler;

    /**
     * The method to get the appropriate {@link EntitiesPersistenceHandler} instance based on {@link EntityType}.
     * 
     * @param entityType
     * @return Instance of {@link EntitiesPersistenceHandler}
     */
    public EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler(final EntityType entityType) throws InvalidEntityException {

        EntitiesPersistenceHandler<? extends AbstractEntity> entitiesPersistenceHandler = null;

        switch (entityType) {

        case CA_ENTITY:
            entitiesPersistenceHandler = cAEntityPersistenceHandler;
            break;

        case ENTITY:
            entitiesPersistenceHandler = entityPersistenceHandler;
            break;

        default:
            throw new InvalidEntityException(ProfileServiceErrorCodes.INVALID_ENTITY_TYPE);
        }
        return entitiesPersistenceHandler;
    }

}
