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

package com.ericsson.oss.itpf.security.kaps.common.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ericsson.oss.itpf.security.kaps.common.Constants;

public class HashGeneratorUtils {

    private HashGeneratorUtils() {

    }

    /**
     * Computes SHA-256 hash.
     * 
     * @param content
     *            content for which hash need to be generated.
     * @return hash of the content.
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateSHA256(final byte[] content) throws NoSuchAlgorithmException {

        return generateHash(content, Constants.SHA_256);
    }

    /**
     * Computes SHA-512 hash.
     * 
     * @param content
     *            content for which hash need to be generated.
     * @return hash of the content.
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateSHA512(final byte[] content) throws NoSuchAlgorithmException {

        return generateHash(content, Constants.SHA_512);
    }

    private static byte[] generateHash(final byte[] content, final String hashAlgorithm) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
        messageDigest.update(content);

        return messageDigest.digest();
    }
}
