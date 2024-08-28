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
 * This class is used to validate signature algorithm in certificate profile.
 * 
 * @author tcsvmeg
 * 
 */
public class SignatureAlgorithmValidator {

    @Inject
    Logger logger;

    @Inject
    private AlgorithmPersistenceHandler algorithmPersistenceHandler;

    /**
     * This method checks if algorithm with given name, type as signature algorithm and supported as true exists in DB
     *
     * @param signatureAlgorithm
     *
     * @throws AlgorithmException
     *
     */
    public void validate(final Algorithm signatureAlgorithm) throws AlgorithmException {
        logger.debug("Validating Signature Algorithm in Certificate Profile {}", signatureAlgorithm);

        final AlgorithmData algorithmData = algorithmPersistenceHandler.getAlgorithmByNameAndType(signatureAlgorithm, AlgorithmType.SIGNATURE_ALGORITHM);

        if (algorithmData == null) {
            logger.error("Given signature algorithm not found or not supported or of invalid category{}", signatureAlgorithm.getName());
            throw new AlgorithmNotFoundException(Constants.GIVEN_ALGORITHM + ProfileServiceErrorCodes.ERR_NOT_FOUND_OR_SUPPORTED);

        }
    }
}
