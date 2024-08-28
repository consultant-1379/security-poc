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
 * This exception is thrown if any protocol exception occurs
 * 
 * @author tcsramc
 * 
 */
public class ProtocolException extends RuntimeException {

    private static final long serialVersionUID = -3753821369789981259L;

    public ProtocolException() {
        super();
    }

    /**
     * Creates an exception with the message
     * 
     * @param message
     *            message to form an exception
     */
    public ProtocolException(final String message) {
        super(message);
    }

    /**
     * Creates an exception with the cause
     * 
     * @param cause
     *            cause of the exception
     */
    public ProtocolException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates an exception with the message
     * 
     * @param errorMessage
     *            message to form an exception
     * @param throwable
     *            error to be thrown
     */
    public ProtocolException(final String errorMessage, final Throwable throwable) {
        super(errorMessage, throwable);
    }
}
