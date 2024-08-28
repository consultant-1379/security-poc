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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;

public class AlgorithmSetUpData {

    private static final String SIGNATURE_ALGORITHM_NAME = "SHA512withRSA";
    private static final int SIGNATURE_ALGORITHM_KEYSIZE = 4096;
    private static final String SIGNATURE_ALGORITHM_OID = "1.2.840.113549.1.1.13";

    private static final String ASYMMETRIC_KEY_ALGORITHM_NAME = "RSA";
    private static final int ASYMMETRIC_KEY_ALGORITHM_KEYSIZE = 512;
    private static final String ASYMMETRIC_KEY_ALGORITHM_OID = "10.11.1.1.13";

    /**
     * Prepares AlgorithmData to check for equals method.
     * 
     * @return {@link AlgorithmData} to compare.
     */
    public AlgorithmData getAlgorithmForEqual() {

        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setId(1);
        algorithmData.setName(SIGNATURE_ALGORITHM_NAME);
        algorithmData.setOid(SIGNATURE_ALGORITHM_OID);
        algorithmData.setSupported(true);
        algorithmData.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        algorithmData.setKeySize(243);
        
        return algorithmData;
    }

    /**
     * Prepares AlgorithmData to check for not equals method.
     * 
     * @return {@link AlgorithmData} to compare.
     */
    public AlgorithmData getAlgorithmForNotEqual() {

        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setName(ASYMMETRIC_KEY_ALGORITHM_NAME);
        algorithmData.setOid(ASYMMETRIC_KEY_ALGORITHM_OID);
        algorithmData.setSupported(true);
        algorithmData.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        algorithmData.setKeySize(243);
       
        return algorithmData;
    }
}
