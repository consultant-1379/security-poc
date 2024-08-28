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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityException;

/**
 * This exception is thrown when the given CAEntity is not valid.
 */
public class InvalidCAException extends CAEntityException {

    private static final long serialVersionUID = -1112886153429900890L;

    /**
     * Constructs a new InvalidCAException
     */
    public InvalidCAException() {
        super();
    }

    /**
     * Constructs a new InvalidCAException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidCAException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidCAException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCAException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCAException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCAException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
