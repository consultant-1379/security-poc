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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.validators;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * This class validates Signature and KeyGeneration algorithms provided for Certificate Profile creation
 */

public class AlgorithmsValidator {

    @Inject
    Logger logger;

    @Inject
    private AlgorithmPersistenceHandler algorithmPersistenceHandler;

    /**
     * This method checks if algorithm with given name, type as signature algorithm and supported as true exists in DB
     * 
     * @param signatureAlgorithm
     * @throws AlgorithmException
     *             if any exception arises when fetching algorithms from database
     * @throws AlgorithmNotFoundException
     *             if any algorithm with given details not found in database.
     */
    public void validateSignatureAlgorithm(final Algorithm signatureAlgorithm) throws AlgorithmException, AlgorithmNotFoundException {
        logger.debug("Validating Signature Algorithm in Certificate Profile {}", signatureAlgorithm);

        if (signatureAlgorithm == null) {
            logger.error("SignatureAlgorithm cannot be null");
            throw new AlgorithmException(ProfileServiceErrorCodes.REQUIRED_ALGORITHM);
        }

        final AlgorithmData algorithmDataFromDB = algorithmPersistenceHandler.getAlgorithmByNameAndType(signatureAlgorithm, AlgorithmType.SIGNATURE_ALGORITHM);

        if (algorithmDataFromDB == null) {
            logger.error("Given signature algorithm not found or not supported or of invalid category{}", signatureAlgorithm.getName());
            throw new AlgorithmNotFoundException(ProfileServiceErrorCodes.GIVEN_ALGORITHM + ProfileServiceErrorCodes.NOT_FOUND_OR_SUPPORTED);

        }
    }

    /**
     * This method checks if at least one key generation algorithm is specified
     * 
     * @param keyGenerationAlgorithmList
     *            list of algorithms
     * @throws AlgorithmException
     *             if any exception arises when fetching algorithms from database
     * @throws AlgorithmNotFoundException
     *             if any algorithm with given details not found in database.
     */
    public void validateKeyGenerationAlgorithms(final List<Algorithm> keyGenerationAlgorithmList) throws AlgorithmException, AlgorithmNotFoundException {
        logger.debug("Validating KeyGenerationAlgorithmList in Certificate Profile {}", keyGenerationAlgorithmList);

        if (ValidationUtils.isNullOrEmpty(keyGenerationAlgorithmList)) {
            logger.error("Keygeneration algorithm cannot be null");
            throw new AlgorithmException(ProfileServiceErrorCodes.REQUIRED_ATLEAST_ONE_KEY_GENERATION_ALGORITHM);
        }
        for (final Algorithm algorithm : keyGenerationAlgorithmList) {
            validateKeyGenerationAlgorithm(algorithm);
        }
    }

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
    public void validateKeyGenerationAlgorithm(final Algorithm keyGenerationAlgorithm) throws AlgorithmException, AlgorithmNotFoundException {

        final AlgorithmData algorithmDataFromDB = algorithmPersistenceHandler.getAlgorithmByNameAndType(keyGenerationAlgorithm, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        if (algorithmDataFromDB == null) {
            logger.error("Given key generation algorithm not found or not supported or of invalid category{}", keyGenerationAlgorithm.getName());
            throw new AlgorithmNotFoundException(ProfileServiceErrorCodes.GIVEN_KEY_GENERATION_ALGORITHM + ProfileServiceErrorCodes.NOT_FOUND_OR_SUPPORTED);
        }

    }

}
