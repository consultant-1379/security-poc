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
 * This Exception is parent exception of all the enrollment related exceptions.
 * 
 */
public class EnrollmentException extends PKIBaseException {

    private static final long serialVersionUID = 2371919714531165785L;

    /**
     * Constructs a new EnrollmentException
     */
    public EnrollmentException() {
        super();
    }

    /**
     * Constructs a new EnrollmentException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public EnrollmentException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EnrollmentException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EnrollmentException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EnrollmentException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EnrollmentException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
