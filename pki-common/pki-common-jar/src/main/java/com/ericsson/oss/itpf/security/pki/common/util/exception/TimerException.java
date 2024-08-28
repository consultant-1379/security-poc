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
package com.ericsson.oss.itpf.security.pki.common.util.exception;

/**
 * This exception is thrown when error occurs while performing operations on EJB timer service.
 * 
 * @author xnagsow
 * 
 */
public class TimerException extends RuntimeException {

    /**
     * 
     */
    private static final long serialVersionUID = -4380517102146128179L;

    public TimerException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     */
    public TimerException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Creates an exception with a message.
     * 
     * @param cause
     *            The cause of the exception.
     */
    public TimerException(final Throwable cause) {
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
    public TimerException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
