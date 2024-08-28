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
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * This class is used to validate KeyGenerationAlgorithm for a {@link CaEntity}
 *
 * @author xtelsow
 */
public class CaEntityKeyGenerationAlgorithm extends AbstractEntityValidator implements CommonValidator<CAEntity> {
    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        validateCaEntityAlgorithm(caEntity);
    }

    /**
     * This method validates the KeyGenerationAlgorithm of caentity i.e {@link CAEntity}
     *
     * @param caEntity
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     * @throws ProfileNotFoundException
     *             is thrown when given Profile doesn't exists or in inactive state.
     * @throws EntityServiceException
     *             is thrown when the exceptions related to entity service occurs.
     * @throws AlgorithmNotFoundException
     *             is thrown when the given algorithm is not found.
     */
    private void validateCaEntityAlgorithm(final CAEntity caEntity) throws AlgorithmNotFoundException, EntityServiceException, MissingMandatoryFieldException, ProfileNotFoundException {
        logger.debug("Validating KeyGenerationAlgorithm for CA Entity {}", caEntity.getCertificateAuthority().getName());

        final EntityProfileData entityProfileData = getEntityProfileFromDB(caEntity.getEntityProfile().getName().trim());

        if (caEntity.getKeyGenerationAlgorithm() != null) {
            validateAlgorithm(caEntity.getKeyGenerationAlgorithm(), entityProfileData);
        } else {
            final int keyGenAlgsSize = entityProfileData.getCertificateProfileData().getKeyGenerationAlgorithms().size();

            if (keyGenAlgsSize > 1) {
                logger.error("Atleast one Key generation algorithm from Certificate Profile should be given in CA entity.");
                throw new MissingMandatoryFieldException("Atleast one Key generation algorithm from Certificate Profile should be given in CA entity.");
            }
        }

        logger.debug("Completed Validating KeyGenerationAlgorithm for CA Entity {}", caEntity.getCertificateAuthority().getName());
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
