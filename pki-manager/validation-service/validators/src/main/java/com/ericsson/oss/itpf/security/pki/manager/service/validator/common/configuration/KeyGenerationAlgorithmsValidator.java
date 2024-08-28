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

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class is used to validate key generation algorithms in certificate profile
 * 
 * @author tcsvmeg
 * 
 */
public class KeyGenerationAlgorithmsValidator {

    @Inject
    Logger logger;

    @Inject
    private KeyGenerationAlgorithmValidator keyGenerationAlgorithmValidator;

    /**
     * This method is used to validate key generation algorithms
     * 
     * @param keyGenerationAlgorithms
     *            list of algorithms
     * @throws AlgorithmException
     *             if any exception arises when fetching algorithms from database
     * @throws AlgorithmNotFoundException
     *             if any algorithm with given details not found in database.
     */
    public void validate(final List<Algorithm> keyGenerationAlgorithms) throws AlgorithmException, AlgorithmNotFoundException {
        logger.debug("Validating KeyGenerationAlgorithmList in Certificate Profile {}", keyGenerationAlgorithms);

        if (ValidationUtils.isNullOrEmpty(keyGenerationAlgorithms)) {
            logger.error("Key generation algorithm(s) cannot be null or empty");
            throw new AlgorithmException(ProfileServiceErrorCodes.ERR_REQUIRED_ATLEAST_ONE_KEY_GENERATION_ALGORITHM);
        }
        for (final Algorithm algorithm : keyGenerationAlgorithms) {
            keyGenerationAlgorithmValidator.validate(algorithm);
        }
    }
}
