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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class validates subjectAltName and subjectAltNameFieldTypes which are present for a {@link CaEntity}
 *
 * @author xtelsow
 */
public class CaEntitySANValidator extends AbstractEntityValidator implements CommonValidator<CAEntity> {

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        validateEntitySubjectAltName(caEntity);
    }

    /**
     * This Method validates the EntitySubjectAltName of CaEntity i.e {@link CAEntity}
     *
     * @param caEntity
     *
     */
    private void validateEntitySubjectAltName(final CAEntity caEntity) throws EntityServiceException, InvalidSubjectAltNameExtension, ProfileNotFoundException {
        logger.debug("Validating EntitySubjectAltName for CA Entity {}", caEntity.getCertificateAuthority().getName());

        if (caEntity.getCertificateAuthority().getSubjectAltName() != null) {
            final EntityProfileData entityProfileData = getEntityProfileFromDB(caEntity.getEntityProfile().getName().trim());
            validateSubjectAltName(caEntity.getCertificateAuthority().getSubjectAltName(), entityProfileData);
        }

        logger.debug("Completed Validating EntitySubjectAltName for CA Entity {}", caEntity);
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
