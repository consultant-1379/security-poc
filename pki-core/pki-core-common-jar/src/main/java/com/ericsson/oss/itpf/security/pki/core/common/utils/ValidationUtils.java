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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.datatype.Duration;

/**
 * Common Util for various operations
 * <p>
 * Validating String pattern like entered Profile Name pattern, DNS Name etc.. Checking if list is empty or null Checking if string is empty or null.
 * </p>
 * 
 */
public class ValidationUtils {

    protected static final String DURATION_PATTERN = "^(?!P0*Y?0*M?0*D?T?0*H?0*M?([0-9]*S)?$)P([0-9]*Y)?([0-9]*M)?([0-9]*D)?T?([0-9]*H)?([0-9]*M)?([0-9]*S)?$";

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
    public static boolean isNullOrEmpty(final Map<?, ?> givenMap) {
        if (givenMap == null || givenMap.isEmpty()) {
            return true;
        }
        return false;
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
     * Method for checking if set is null or empty
     * 
     * @param givenSet
     *            set of objects
     * @return true or false
     */
    public static boolean isNullOrEmpty(final Set<?> givenSet) {
        if (givenSet == null || givenSet.isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * Method for checking if string is null or empty
     * 
     * @param str
     *            String value that is checked for empty or null
     * @return true or false
     */
    public static boolean isNullOrEmpty(final String str) {
        if (str == null || str.trim().length() == 0) {
            return true;
        }

        return false;
    }

    /**
     * Method for checking if String is having ?
     * 
     * @param str
     *            String is having single ? symbol
     * @return true or false
     */
    public static boolean isValidSubjectString(final String str) {
        if ((str.length() == 1) && (str.compareTo("?") == 0)) {
            return true;
        }

        return false;
    }

    /**
     * Method for checking if given character is valid ASCII printable character
     * 
     * @param ch
     *            Character value that is checked whether ASCII printable or not
     * @return true or false
     */
    public static boolean isAsciiPrintable(final char ch) {
        return ch >= 0x0020 && ch < 0x007f;
    }

    /**
     * Method for checking if given String is valid ASCII printable
     * 
     * @param ch
     *            String value that is checked whether ASCII printable or not
     * @return true or false
     */
    public static boolean isAsciiPrintable(final String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            final char ch = str.charAt(i);

            if (!isAsciiPrintable(ch)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param time
     * @return
     */
    public static boolean validateDurationFormat(final Duration time) {

        final String duration = time.toString();

        if (!ValidationUtils.validatePattern(DURATION_PATTERN, duration)) {
            return false;
        }
        return true;
    }
}