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
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class is used to validate KeyGenerationAlgorithm for a {@link Entity}
 *
 * @author xtelsow
 */
public class EntityKeyGenerationAlgorithmValidator extends AbstractEntityValidator implements CommonValidator<Entity> {
    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {

        validateEntityAlgorithm(entity);

    }

    /**
     * This method validates the KeyGenerationAlgorithm of entity i.e {@link Entity}
     *
     * @param entity
     *
     */
    private void validateEntityAlgorithm(final Entity entity) throws AlgorithmNotFoundException, EntityServiceException, MissingMandatoryFieldException, ProfileNotFoundException {
        logger.debug("Validating KeyGenerationAlgorithm for Entity {}", entity.getKeyGenerationAlgorithm());
        final EntityProfileData entityProfileData = getEntityProfileFromDB(entity.getEntityProfile().getName().trim());
        if (entity.getKeyGenerationAlgorithm() != null) {
            validateAlgorithm(entity.getKeyGenerationAlgorithm(), entityProfileData);
        }
        logger.debug("Completed Validating KeyGenerationAlgorithm for  Entity {}", entity.getKeyGenerationAlgorithm());
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
