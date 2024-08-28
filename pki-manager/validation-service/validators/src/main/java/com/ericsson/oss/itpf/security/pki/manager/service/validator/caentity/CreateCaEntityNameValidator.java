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
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class is used to validate name for a {@link CaEntity} during create operation.
 *
 * @author xtelsow
 */
public class CreateCaEntityNameValidator extends AbstractEntityValidator implements CommonValidator<CAEntity> {

    @Inject
    Logger logger;

    private final static String NAME_PATH = "certificateAuthorityData.name";

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        validateCaEntityName(caEntity);
    }

    /**
     * This Method validates the name of caentity i.e {@link CAEntity}
     *
     * @param caEntity
     *
     *
     */
    private void validateCaEntityName(final CAEntity caEntity) throws EntityAlreadyExistsException, EntityServiceException, InvalidEntityAttributeException {
        logger.debug("Validating create CA Entity {}", caEntity.getCertificateAuthority().getName());

        final String trimmedName = caEntity.getCertificateAuthority().getName().trim();
        caEntity.getCertificateAuthority().setName(trimmedName);

        checkEntityNameFormat(caEntity.getCertificateAuthority().getName());
        checkNameAvailability(caEntity.getCertificateAuthority().getName(), CAEntityData.class, NAME_PATH);

        logger.debug("Completed validating create CA Entity", caEntity.getCertificateAuthority().getName());
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
