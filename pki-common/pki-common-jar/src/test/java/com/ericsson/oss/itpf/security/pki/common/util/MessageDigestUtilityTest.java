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

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.setUp.KeyStoreSetUP;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidAlgorithmException;

/**
 * This class is a junit test class for MessageDigestUtility class.
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class MessageDigestUtilityTest extends KeyStoreSetUP {

    @InjectMocks
    private MessageDigestUtility messageDigestUtility;

    private static String message = null;
    private static String filePath = "src/test/resources/PKCSRequest.p7m";

    /**
     * This method is used to set up valid PKCS message.
     * 
     */
    @Before
    public void setUp() {
        message = readFile(filePath);
    }

    /**
     * Test case for checking generateMessageDigest method by using valid digest algorithm.
     * 
     */
    @Test
    public void testGenerateMessageDigest() {
        final byte[] encodedData = message.getBytes();
        String algorithm = "MD5";
        byte[] messageDigest = MessageDigestUtility.generateMessageDigest(algorithm, encodedData);
        assertEquals(16, messageDigest.length);
    }

    /**
     * Test case for checking generateMessageDigest method for InvalidAlgorithmException,by passing invalid message digest algorithm.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidAlgorithmException.class)
    public void testGenerateMessageDigestException() {
        final byte[] encodedData = message.getBytes();
        String algorithm = "RSA";
        MessageDigestUtility.generateMessageDigest(algorithm, encodedData);
    }

}
