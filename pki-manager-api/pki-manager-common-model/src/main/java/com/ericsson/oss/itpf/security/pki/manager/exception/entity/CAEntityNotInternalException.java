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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity;

/**
 * This Exception is thrown when given CA Entity exists but it's an external CA.
 *
 */
public class CAEntityNotInternalException extends EntityNotFoundException {

    private static final long serialVersionUID = 1L;

    public CAEntityNotInternalException() {
        super();
    }

    /**
     * Constructs a new CAEntityNotInternalException with detailed message
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public CAEntityNotInternalException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new CAEntityNotInternalException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CAEntityNotInternalException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CAEntityNotInternalException with detailed message and cause
     *
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CAEntityNotInternalException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
