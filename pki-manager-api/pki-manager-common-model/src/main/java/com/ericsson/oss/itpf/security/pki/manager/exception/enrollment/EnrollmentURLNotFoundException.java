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
package com.ericsson.oss.itpf.security.pki.manager.exception.enrollment;

import com.ericsson.oss.itpf.security.pki.manager.exception.EnrollmentException;

/**
 * This exception is thrown when the enrollment URL is not found.
 */
public class EnrollmentURLNotFoundException extends EnrollmentException {

    private static final long serialVersionUID = 848551310302590568L;

    /**
     * Constructs a new EnrollmentURLNotFoundException
     */
    public EnrollmentURLNotFoundException() {
        super();
    }

    /**
     * Constructs a new EnrollmentURLNotFoundException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public EnrollmentURLNotFoundException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EnrollmentURLNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EnrollmentURLNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EnrollmentURLNotFoundException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EnrollmentURLNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
