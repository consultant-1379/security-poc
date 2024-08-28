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
package com.ericsson.oss.itpf.security.kaps.common.utils;

//To-do: This has to be moved to pki-common

/**
 * Utility class to convert text to binary
 * 
 */
public class TextToBinaryUtility {
    
    private TextToBinaryUtility() {
    }

    /**
     * Method for converting text to binary
     * 
     * @param text
     *            String that has to be converted to binary
     * @param textInBinary
     *            binary String.
     * @return binary equivalent of input text
     */
    public static boolean[] getTextAsBinary(final String text) {
        boolean[] textInBinary = null;

        if (text != null) {
            final char[] textInChars = text.toCharArray();
            textInBinary = new boolean[textInChars.length * 8];

            for (int i = 0; i != textInBinary.length; i++) {
                textInBinary[i] = (textInChars[i / 8] & (0x80 >>> (i % 8))) != 0;
            }
        }

        return textInBinary;
    }
}
