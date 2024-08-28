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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;

public class KeyGenerationAlgorithmSetUpData {

    private static final String EQUAL_ASYMMETRIC_KEY_ALGORITHM_NAME = "RSA";
    private static final int EQUAL_ASYMMETRIC_KEY_ALGORITHM_KEYSIZE = 512;
    private static final String EQUAL_ASYMMETRIC_KEY_ALGORITHM_OID = "10.11.1.1.13";
    private static final String NOT_EQUAL_ASYMMETRIC_KEY_ALGORITHM_NAME = "DSA";
    private static final int NOT_EQUAL_ASYMMETRIC_KEY_ALGORITHM_KEYSIZE = 1024;
    private static final String NOT_EQUAL_ASYMMETRIC_KEY_ALGORITHM_OID = "10.11.1.1.16";

    /**
     * Method that returns valid Algorithm
     * 
     * @return Algorithm
     */
    public Algorithm getAlgorithmForEqual() {
        return new AlgorithmSetUpData().name(EQUAL_ASYMMETRIC_KEY_ALGORITHM_NAME).keySize(EQUAL_ASYMMETRIC_KEY_ALGORITHM_KEYSIZE).oid(EQUAL_ASYMMETRIC_KEY_ALGORITHM_OID).supported(true)
                .type(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM).build();
    }

    /**
     * Method that returns different valid Algorithm
     * 
     * @return Algorithm
     */
    public Algorithm getAlgorithmForNotEqual() {
        return new AlgorithmSetUpData().name(NOT_EQUAL_ASYMMETRIC_KEY_ALGORITHM_NAME).keySize(NOT_EQUAL_ASYMMETRIC_KEY_ALGORITHM_KEYSIZE).oid(NOT_EQUAL_ASYMMETRIC_KEY_ALGORITHM_OID).supported(false)
                .type(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM).build();
    }
}
