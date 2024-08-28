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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;

/**
 * This class is used to validate key generation algorithm
 * 
 * @author tcsvmeg
 * 
 */
public class KeyGenerationAlgorithmValidator {

    @Inject
    Logger logger;

    @Inject
    private AlgorithmPersistenceHandler algorithmPersistenceHandler;

    /**
     * This method checks whether given algorithm name and key size combination is present in database with type as KeyGenerationAlgorithm and supported as true.
     * 
     * @param keyGenerationAlgorithm
     * 
     * @throws AlgorithmException
     *             if any exception arises when fetching algorithms from database
     * @throws AlgorithmNotFoundException
     *             if any algorithm with given details not found in database.
     * 
     */
    public void validate(final Algorithm keyGenerationAlgorithm) throws AlgorithmException, AlgorithmNotFoundException {

        if (keyGenerationAlgorithm == null) {
            logger.error("KeyGenerationAlgorithm cannot be null");
            throw new AlgorithmException(ProfileServiceErrorCodes.ERR_REQUIRED_KEY_GEN_ALGORITHM);
        }

        final AlgorithmData algorithmData = algorithmPersistenceHandler.getAlgorithmByNameAndType(keyGenerationAlgorithm, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        if (algorithmData == null) {
            logger.error("Given key generation algorithm not found or not supported or of invalid category{}", keyGenerationAlgorithm.getName());
            throw new AlgorithmNotFoundException(Constants.GIVEN_KEY_GENERATION_ALGORITHM + ProfileServiceErrorCodes.ERR_NOT_FOUND_OR_SUPPORTED);
        }

    }
}
