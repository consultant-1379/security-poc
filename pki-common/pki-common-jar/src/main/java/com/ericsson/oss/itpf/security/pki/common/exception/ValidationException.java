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
package com.ericsson.oss.itpf.security.pki.common.exception;

/**
 * This exception is thrown if any validation fails
 * 
 * @author tcsramc
 * 
 */
public class ValidationException extends RuntimeException {

    private static final long serialVersionUID = 1899217340422652295L;

    public ValidationException() {
        super();
    }

    /**
     * Creates an exception with the message
     * 
     * @param message
     *            message to form an exception
     */
    public ValidationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Creates an exception with the message
     * 
     * @param errorMessage
     *            message to form an exception
     * @param throwable
     *            error to be thrown
     */
    public ValidationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

    /**
     * Creates an exception with the cause
     * 
     * @param cause
     *            cause of the exception
     */
    public ValidationException(final Throwable cause) {
        super(cause);
    }
}
