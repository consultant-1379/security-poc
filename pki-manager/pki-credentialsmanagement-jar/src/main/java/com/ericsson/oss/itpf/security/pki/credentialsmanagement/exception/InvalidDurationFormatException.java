/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception;

/**
 * This exception is thrown when fail to convert a String to Duration.
 * 
 * @author xramdag
 * 
 */
// TODO: This exception will be moved to pki-common as part of MS6 Bug fixes.Refactoring will be done once that goes to master.
public class InvalidDurationFormatException extends RuntimeException {

    /**
     * 
     */
    private static final long serialVersionUID = -5591528822018407566L;

    public InvalidDurationFormatException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     */
    public InvalidDurationFormatException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Creates an exception with a message.
     * 
     * @param cause
     *            The cause of the exception.
     */
    public InvalidDurationFormatException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */
    public InvalidDurationFormatException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
