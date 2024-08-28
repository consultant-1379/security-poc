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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.extension;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.AlgorithmSetUpData;

/**
 * This class is used to run Junits for KeyIdentifier objects in different scenarios
 */
public class KeyIdentifierTest extends EqualsTestCase {

    private static final String SIGNATURE_ALGORITHM_NAME = "SHA512withRSA";
    private static final int SIGNATURE_ALGORITHM_KEYSIZE = 4096;
    private static final String SIGNATURE_ALGORITHM_OID = "1.2.840.113549.1.1.13";
    private static final String ASYMMETRIC_KEY_ALGORITHM_NAME = "RSA";
    private static final int ASYMMETRIC_KEY_ALGORITHM_KEYSIZE = 512;
    private static final String ASYMMETRIC_KEY_ALGORITHM_OID = "10.11.1.1.13";

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    public Object createInstance() {
        final KeyIdentifier keyIdentifier = new KeyIdentifier();

        final List<AlgorithmCategory> algorithmCategories = new ArrayList<AlgorithmCategory>();
        algorithmCategories.add(AlgorithmCategory.KEY_IDENTIFIER);

        final Algorithm algorithm = (new AlgorithmSetUpData()).name(SIGNATURE_ALGORITHM_NAME).keySize(SIGNATURE_ALGORITHM_KEYSIZE).oid(SIGNATURE_ALGORITHM_OID).type(AlgorithmType.SIGNATURE_ALGORITHM)
                .algorithmCategories(algorithmCategories).build();

        keyIdentifier.setAlgorithm(algorithm);
        keyIdentifier.setKeyIdentifer("KeyIdentifier1");

        return keyIdentifier;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    public Object createNotEqualInstance() {
        final KeyIdentifier keyIdentifier = new KeyIdentifier();

        final List<AlgorithmCategory> algorithmCategories = new ArrayList<AlgorithmCategory>();
        algorithmCategories.add(AlgorithmCategory.KEY_IDENTIFIER);

        final Algorithm algorithm = (new AlgorithmSetUpData()).name(ASYMMETRIC_KEY_ALGORITHM_NAME).keySize(ASYMMETRIC_KEY_ALGORITHM_KEYSIZE).oid(ASYMMETRIC_KEY_ALGORITHM_OID).supported(true)
                .type(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM).algorithmCategories(algorithmCategories).build();

        keyIdentifier.setAlgorithm(algorithm);
        keyIdentifier.setKeyIdentifer("KeyIdentifier2");

        return keyIdentifier;
    }
}
