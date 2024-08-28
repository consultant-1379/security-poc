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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidAlgorithmException;

/**
 * This class performs Cryptographic operations like preparing Message Digest.
 * 
 * @author xkarlak
 */
public class MessageDigestUtility {

    private static final Logger logger = LoggerFactory.getLogger(MessageDigestUtility.class);

    private MessageDigestUtility() {

    }

    /**
     * This method returns generated hash value as byte array. this hash value is generated on the provided data by using specified algorithm.
     * 
     * @param algorithm
     *            name of the algorithm used to generate MessageDigest.
     * 
     * @param data
     *            for which need to do MessageDigest.
     * 
     * @return byte[] is the array of bytes for the resulting hash value.
     * 
     * @throws InvalidAlgorithmException
     *             is thrown if the invalid algorithm is provided for generating Message Digest.
     */
    // TODO: The parameter algorithm will be replaced with Algorithm object which used in PKI-Manager once the PKI-common model is moved to PKI-Common Repo. User story ref : TORF-53695.
    public static byte[] generateMessageDigest(final String algorithm, final byte[] data) throws InvalidAlgorithmException {
        logger.info("Start of generateMessageDigest method in MessageDigestUtility class");
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(data);
        } catch (final NoSuchAlgorithmException e) {
            logger.error("Invalid Algorithm for generating Message Digest", e.getMessage());
            throw new InvalidAlgorithmException(ErrorMessages.NO_SUCH_ALGORITHM, e);
        }
        logger.info("End of generateMessageDigest method in MessageDigestUtility class");
        return messageDigest.digest();

    }
}
