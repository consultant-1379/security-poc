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
package com.ericsson.oss.itpf.security.pki.manager.rest.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;

/**
 * Class for building dummy algorithm objects for tests
 * 
 * @author tcspred
 * 
 */
public class AlgorithmSetUpToTest {

    Algorithm signatureAlgorithm = new Algorithm();
    List<Algorithm> keyGenAlgorithms = new ArrayList<Algorithm>();

    public AlgorithmSetUpToTest() {
        getSignatureAlgorithm();
        getKeyGenerationAlgorithmList();
    }

    /**
     * Method to provide dummy SignatureAlgorithm for tests.
     */
    public Algorithm getSignatureAlgorithm() {
        final List<AlgorithmCategory> categories = new ArrayList<AlgorithmCategory>();
        categories.add(AlgorithmCategory.OTHER);

        signatureAlgorithm.setKeySize(2048);
        signatureAlgorithm.setName("TestSA");
        signatureAlgorithm.setOid("0.1.2");
        signatureAlgorithm.setSupported(true);
        signatureAlgorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        signatureAlgorithm.setCategories(categories);
        return signatureAlgorithm;
    }

    /**
     * Method to provide dummy KeyGenerationAlgorithms for tests.
     */
    public List<Algorithm> getKeyGenerationAlgorithmList() {
        final Algorithm keyGenAlgorithm = new Algorithm();

        keyGenAlgorithm.setKeySize(2048);
        keyGenAlgorithm.setName("TestKGA");
        keyGenAlgorithm.setOid("0.1.2");
        keyGenAlgorithm.setSupported(true);
        keyGenAlgorithm.setType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM);

        keyGenAlgorithms.add(keyGenAlgorithm);
        return keyGenAlgorithms;
    }
}
