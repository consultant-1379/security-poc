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
package com.ericsson.itpf.security.pki.cmdhandler.util;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ValidationUtilsTest {

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils#validatePattern(java.lang.String, java.lang.String)}.
     */
    @Test
    public void testValidatePattern() {
        assertTrue(ValidationUtils.validatePattern("\\d-\\d?", "1-1"));
    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils#isNullOrEmpty(java.util.List)}.
     */
    @Test
    public void testIsNullOrEmptyListOfQ() {
        List<String> list = null;
        assertTrue(ValidationUtils.isNullOrEmpty(list));
    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils#isNullOrEmpty(java.lang.String)}.
     */
    @Test
    public void testIsNullOrEmptyString() {
        assertTrue(ValidationUtils.isNullOrEmpty(""));
        String nullstring = null;
        assertTrue(ValidationUtils.isNullOrEmpty(nullstring));
    }

}
