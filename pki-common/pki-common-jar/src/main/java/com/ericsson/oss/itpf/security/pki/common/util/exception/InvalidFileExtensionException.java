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
package com.ericsson.oss.itpf.security.pki.common.util.exception;

/**
 * This exception is thrown if any unsupported file extension encounters.
 * 
 * @author tcsramc
 * 
 */
public class InvalidFileExtensionException extends RuntimeException {

    private static final long serialVersionUID = 8385230875323723597L;
    private String errorMessage;

    public InvalidFileExtensionException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     */
    public InvalidFileExtensionException(final String message) {
        this.errorMessage = message;
    }

    /**
     * Return errorMessage.
     * 
     * @return
     */

    public String getErrorMessage() {
        return errorMessage;
    }

}
