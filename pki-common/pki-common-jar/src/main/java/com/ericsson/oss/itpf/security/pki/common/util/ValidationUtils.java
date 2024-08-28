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

import java.util.List;

/**
 * Common Util for various operations
 * <p>
 * Validating String pattern like entered Profile Name pattern, DNS Name etc.. Checking if list is empty or null Checking if string is empty or null.
 * </p>
 * 
 * @author xjagcho
 */
public final class ValidationUtils {
    private ValidationUtils() {
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

}