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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import java.security.SecureRandom;

/**
 * This class generates a random Id.
 * 
 * @author tcsramc
 * 
 */
public class Base64EncodedIdGenerator {

    private Base64EncodedIdGenerator() {

    }

    /**
     * Generates and returns a randomID.
     * 
     * @return Base64 Encoded ID
     */
    public static String generate() {
        final String generatedID = new String(org.bouncycastle.util.encoders.Base64.encode(getRandomArray(16)));
        return generatedID;
    }

    private static byte[] getRandomArray(final int length) {
        final byte[] result = new byte[length];
        final SecureRandom randomGenerator = new SecureRandom();
        randomGenerator.nextBytes(result);
        return result;
    }

}
