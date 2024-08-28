/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 * 
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception;

/**
 * This exception is the parent exception of all the exceptions related to certificate and certificate fields.
 */
public class SecurityException extends PKIBaseException {

    private static final long serialVersionUID = -100658136326988324L;

    /**
     * Constructs a new SecurityException
     */
    public SecurityException() {
        super();
    }

    /**
     * Constructs a new SecurityException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public SecurityException(final String message) {
        super(message);
    }

    /**
     * Constructs a new SecurityException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public SecurityException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new SecurityException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public SecurityException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
