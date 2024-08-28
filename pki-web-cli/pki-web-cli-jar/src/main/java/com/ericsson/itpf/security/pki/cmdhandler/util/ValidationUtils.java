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

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;

/**
 * Common Util for various operations
 * <p>
 * Validating String pattern like entered Profile Name pattern, DNS Name etc.. Checking if list is empty or null Checking if string is empty or null
 * </p>
 * 
 */
public final class ValidationUtils {
    private ValidationUtils() {
    }

    /**
     * Method for validating the String against pattern
     * 
     * @param patternString
     *            Pattern that is to used for validation of String.
     * @param value
     *            String value that is to validated against pattern.
     * @return true or false
     */
    public static boolean validatePattern(final String patternString, final String value) {
        final Pattern pattern = Pattern.compile(patternString, Pattern.CASE_INSENSITIVE);
        final Matcher matcher = pattern.matcher(value);

        return matcher.matches();
    }

    /**
     * Method for checking if list is null or empty
     * 
     * @param givenList
     *            list of objects
     * @return true or false
     */
    public static boolean isNullOrEmpty(final List<?> givenList) {
        if (givenList == null || givenList.isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * Method for checking if string is null or empty
     * 
     * @param string
     *            String value that is checked for empty or null
     * @return true or false
     */
    public static boolean isNullOrEmpty(final String string) {
        if (string == null || string.length() == 0) {
            return true;
        }

        return false;
    }

    /**
     * Method for checking if String array is null or empty
     * 
     * @param string
     * @return true or false
     */
    public static boolean isNullOrEmpty(final String[] string) {
        if (string == null || string.length == 0) {
            return true;
        }

        return false;

    }

    /**
     * Method for checking if boolean value is true or false
     * 
     * @param boolean
     * @return String
     */
    public static String isTrueOrFalse(final boolean value) {

        return value ? Constants.TRUE : Constants.FALSE;

    }
}
