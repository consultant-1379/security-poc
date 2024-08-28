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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.data;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * This class populates dummy data for Algorithm related models
 * 
 * @author xnagcho
 * @version 1.1.30
 * 
 */
public class AlgorithmDataSetUp {

    /**
     * Method that returns key generation algorithm
     * 
     * @return key generation algorithm
     */
    public AlgorithmData getSupportedKeyGenerationAlgorithm() {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setId(4);
        algorithmData.setName("RSA");
        algorithmData.setKeySize(2048);
        algorithmData.setSupported(true);
        algorithmData.setType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.getId());

        return algorithmData;
    }

    /**
     * Method that returns signature algorithm
     * 
     * @return signature algorithm
     */
    public AlgorithmData getSupportedSignatureAlgorithm() {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setId(6);
        algorithmData.setName("SHA256withRSA");
        algorithmData.setKeySize(0);
        algorithmData.setSupported(true);
        algorithmData.setType(AlgorithmType.SIGNATURE_ALGORITHM.getId());

        return algorithmData;
    }

    /**
     * Method that returns list of key generation algorithms
     * 
     * @return list of key generation algorithms
     */
    public Set<AlgorithmData> getKeyGenerationAlgorithmList() {
        final Set<AlgorithmData> algorithms = new HashSet<AlgorithmData>();
        algorithms.add(getSupportedKeyGenerationAlgorithm());

        return algorithms;
    }

}
