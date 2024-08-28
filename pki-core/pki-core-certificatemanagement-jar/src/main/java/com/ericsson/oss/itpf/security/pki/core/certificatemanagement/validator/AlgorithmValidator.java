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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;

/**
 * Class that provides method to validate Algorithm that is passed from PKI Manager.
 *
 */
public class AlgorithmValidator {

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Checks algorithm exists in the database or not and supported or not.
     *
     * @param algorithm
     *            {@link AlgorithmData} object to be validated.
     * @throws AlgorithmValidationException
     *             Thrown incase algorithm not found in the database.
     */
    public void validateAlgorithm(final Algorithm algorithm) throws AlgorithmValidationException {

        logger.debug("Validating algorithm whether present in database  {}", algorithm);

        if (persistenceHelper.getAlgorithmData(algorithm) == null) {
            logger.error("Algorithm {} not found in the database", algorithm);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "AlgorithmValidator", "Algorithm", "Algorithm "
                    + algorithm + " not found in the database");
            throw new AlgorithmValidationException(ErrorMessages.ALGORITHM_NOT_FOUND_IN_DATABASE);
        }

        logger.debug("Algorithm {} exists in PKI core database", algorithm);
    }

}
