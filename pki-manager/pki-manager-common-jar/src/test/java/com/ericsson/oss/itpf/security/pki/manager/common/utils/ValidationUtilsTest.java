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
package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;

@RunWith(MockitoJUnitRunner.class)
public class ValidationUtilsTest {

    /*
     * Method to test Valid Pattern
     */
    @Test
    public void validatePattern_validData() {
        final boolean isValid = ValidationUtils.validatePattern("^[a-zA-Z0-9_-]{3,255}$", "testProfile");
        assertTrue(isValid);
    }

    /*
     * Method to test null List
     */
    @Test
    public void isNullOrEmpty_List() {
        final List<String> list = null;
        final boolean isValid = ValidationUtils.isNullOrEmpty(list);
        assertTrue(isValid);
    }

    /*
     * Method to test Valid List
     */
    @Test
    public void isNullOrEmpty_ValidList() {
        final List<String> list = new ArrayList<String>();
        list.add("profile");
        final boolean isValid = ValidationUtils.isNullOrEmpty(list);
        assertFalse(isValid);

    }

    /*
     * Method to test null List
     */
    @Test
    public void isNullOrEmpty_String() {
        final String str = null;
        final boolean isValid = ValidationUtils.isNullOrEmpty(str);
        assertTrue(isValid);
    }

    /*
     * Method to test valid List
     */
    @Test
    public void isNullOrEmpty_ValidString() {
        final String str = "profile";
        final boolean isValid = ValidationUtils.isNullOrEmpty(str);
        assertFalse(isValid);
    }

    /*
     * Method to test valid subject string
     */
    @Test
    public void isValidSubjectString_ValidString() {
        final String str = "?";
        final boolean isValid = ValidationUtils.isValidSubjectString(str);
        assertTrue(isValid);
    }

    /*
     * Method to test Invalid subject string
     */
    @Test
    public void isValidSubjectString_InvalidString() {
        final String str = "??";
        final boolean isValid = ValidationUtils.isValidSubjectString(str);
        assertFalse(isValid);
    }

    /*
     * Method to test valid subject string
     */
    @Test
    public void isAsciiPrintable_ValidString() {
        final String str = "?";
        final boolean isValid = ValidationUtils.isAsciiPrintable(str);
        assertTrue(isValid);
    }

    /*
     * Method to test valid Integer
     */
    @Test
    public void isNullOrEmpty_Integer() {

        Integer val = new Integer(5);
        final boolean isValid = ValidationUtils.isNullOrEmpty(val);
        assertFalse(isValid);
    }

    /*
     * Method to test valid Integer null
     */
    @Test
    public void isNullOrEmpty_Integer_null() {

        Integer val = null;
        final boolean isValid = ValidationUtils.isNullOrEmpty(val);
        assertTrue(isValid);
    }

    /*
     * Method to test valid Integer null
     */
    @Test
    public void isNullOrEmpty_Map() {
        Map<String,String> map = null;
        final boolean isValid = ValidationUtils.isNullOrEmpty(map);
        assertTrue(isValid);
    }

    @Test
    public void isNullOrEmpty_Map_value() {
        Map<String,String> map = new HashMap<String, String>();
        map.put("name", "test");
        final boolean isValid = ValidationUtils.isNullOrEmpty(map);
        assertFalse(isValid);
    }



}
