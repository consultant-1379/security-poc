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
package com.ericsson.oss.itpf.security.pki.common.certificatemanagement.generator;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.inject.Inject;

import org.slf4j.Logger;

/**
 * Generates {@link KeyPair} with given key generation algorithm and key size.
 */
public class KeyPairGenerator {

    @Inject
    Logger logger;

    /**
     * Generates KeyPair using keyPair algorithm and key size
     * 
     * @param keyPairAlgorithm
     *            The algorithm for generating keys.
     * @param keySize
     *            The key size.
     * @return KeyPair generated {@link KeyPair} object
     * @throws NoSuchAlgorithmException
     *             Thrown if Provided Key generation algorithm is not found.
     */
    public KeyPair generateKeyPair(final String keyPairAlgorithm, final int keySize) throws NoSuchAlgorithmException {

        logger.debug("Key Pair generation started with {} and key size is {}", keyPairAlgorithm, keySize);

        final java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(keySize);
        final KeyPair keyPair = gen.generateKeyPair();

        logger.debug("Key Pair generated with {} and key size is {}", keyPairAlgorithm, keySize);
        return keyPair;

    }
}