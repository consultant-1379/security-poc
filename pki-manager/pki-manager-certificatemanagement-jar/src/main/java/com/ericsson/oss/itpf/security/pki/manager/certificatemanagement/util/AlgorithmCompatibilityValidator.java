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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;

/**
 * To-Do: This class will be removed, once permanent fix for TORF-119828 is given in future
 * 
 * <p>
 * This class is used to validate if the input signature and key generation algorithms are compatible.
 * </p>
 */
public class AlgorithmCompatibilityValidator {

    @Inject
    Logger logger;

    /**
     * To-Do: Just added as a temporary fix for https://jira-nam.lmera.ericsson.se/browse/TORF-119828. This will be removed in future
     * 
     * Checks if signature and key generation algorithms given in certificateGenerationInfo object are compatible.
     * 
     * @param signatureAlgorithm
     *            {@link Algorithm} object to be validated.
     * 
     * @param keyGenerationAlgorithm
     *            {@link Algorithm} object to be validated.
     * 
     * @throws InvalidEntityAttributeException
     *             Thrown in case of algorithms of Entity are found compatible.
     */
    public void checkSignatureAndKeyGenerationAlgorithms(String signatureAlgorithmName, final String keyGenerationAlgorithmName) throws InvalidEntityAttributeException {

        logger.debug("Checking if given signature algorithm {} and key generation algorithm {} are compatible", signatureAlgorithmName, keyGenerationAlgorithmName);

        signatureAlgorithmName = signatureAlgorithmName.substring(signatureAlgorithmName.indexOf("with") + 4, signatureAlgorithmName.length());

        if (!signatureAlgorithmName.equals(keyGenerationAlgorithmName)) {
            throw new InvalidEntityAttributeException(ErrorMessages.INCOMPATIBLE_SIGNATURE_KEYGEN_ALGORITHMS);
        }

        logger.debug("Given signature algorithm {} and key generation algorithm {} are found compatible!", signatureAlgorithmName, keyGenerationAlgorithmName);
    }
}
