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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * This class is a junit test class for StringUtility class.
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class StringUtilityTest {

    @InjectMocks
    private static StringUtility stringUtility;

    private static String validMessage = "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";
    private static String invalidMessage = "InvalidMessage";

    /**
     * Test case for checking isBase64() method by passing validMessage.
     * 
     */
    @Test
    public void testIsBase64() {
        final boolean isBase64 = StringUtility.isBase64(validMessage);
        assertTrue(isBase64);

    }

    /**
     * Test case for checking isBase64() method by passing invalidMessage.
     * 
     */
    @Test
    public void testIsBase64Fail() {
        final boolean isBase64 = StringUtility.isBase64(invalidMessage);
        assertFalse(isBase64);
    }

}
