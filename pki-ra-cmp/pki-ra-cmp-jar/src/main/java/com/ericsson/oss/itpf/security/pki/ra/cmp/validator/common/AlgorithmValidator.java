/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.UnsupportedAlgorithmException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.RequestValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.SupportedAlgorithmsCacheWrapper;

/**
 * This validator will validate if the protection algorithm in the requestMessage is supported by PKI-system. There is algorithmDataCache which holds
 * all supported algorithms.
 * 
 * @author tcsdemi
 */
public class AlgorithmValidator implements RequestValidator {

    @Inject
    SupportedAlgorithmsCacheWrapper supportedAlgorithmsCacheWrapper;

    @Inject
    Logger logger;

    @Override
    public void validate(final RequestMessage pKIRequestMessage) throws UnsupportedAlgorithmException {

        final String algorithmID = pKIRequestMessage.getProtectionAlgorithmID();
        final AlgorithmType algorithmType = AlgorithmType.SIGNATURE_ALGORITHM;

        logger.info("ALGORITHM OID {}" , algorithmID);
        logger.info("ALGORITHM TYPE {}" , algorithmType);
        final List<String> listOfAlgOid = supportedAlgorithmsCacheWrapper.get(algorithmType.value());

        if (algorithmID == null) {
            logger.error("Required Algorithm Oid is Null");
            throw new UnsupportedAlgorithmException(ErrorMessages.INVALID_ALGORITHM);
        }

        if (listOfAlgOid == null) {
            logger.error("Supported algorithms are not found in cache");
            throw new UnsupportedAlgorithmException(ErrorMessages.ALGORITHM_OID_NOT_PRESENT_IN_CACHE);
        }

        if (!listOfAlgOid.contains(algorithmID)) {
            logger.error("Algorithm with oid value {} is not supported", algorithmID);
            throw new UnsupportedAlgorithmException(ErrorMessages.ALGORITHM_NOT_SUPPORTED);
        }
    }

}
