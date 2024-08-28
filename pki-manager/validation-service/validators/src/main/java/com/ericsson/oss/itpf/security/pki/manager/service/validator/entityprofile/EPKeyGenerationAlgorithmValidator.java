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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.KeyGenerationAlgorithmValidator;

/**
 * This class validates keygeneration algorithm present in {@link EntityProfile} .
 * 
 * @author tcsvmeg
 * 
 */
public class EPKeyGenerationAlgorithmValidator implements CommonValidator<EntityProfile> {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Inject
    KeyGenerationAlgorithmValidator keyGenerationAlgorithmValidator;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateKeyGenerationAlgorithm(entityProfile);
    }

    private void validateKeyGenerationAlgorithm(final EntityProfile entityProfile) throws AlgorithmException, AlgorithmNotFoundException {
        final Algorithm keyGenerationAlgorithm = entityProfile.getKeyGenerationAlgorithm();

        if (keyGenerationAlgorithm == null || ValidationUtils.isNullOrEmpty(keyGenerationAlgorithm.getName())) {
            return;
        }

        keyGenerationAlgorithmValidator.validate(keyGenerationAlgorithm);
    }
}