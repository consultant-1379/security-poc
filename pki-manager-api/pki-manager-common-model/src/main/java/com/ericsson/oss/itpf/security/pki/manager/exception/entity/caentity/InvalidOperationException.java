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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityException;

/**
 * This exception is thrown when the given CA is not root CA.
 */
public class InvalidOperationException extends CAEntityException {

    private static final long serialVersionUID = -1112886153429900990L;

    /**
     * Constructs a new InactiveCAException
     */
    public InvalidOperationException() {
        super();
    }

    /**
     * Constructs a new InactiveCAException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidOperationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InactiveCAException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidOperationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InactiveCAException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidOperationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
