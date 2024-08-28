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
package com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement;

import com.ericsson.oss.itpf.security.pki.core.exception.CoreEntityException;

/**
 * This Exception is thrown when given Entity doesn't exists.
 *
 */
public class CoreEntityNotFoundException extends CoreEntityException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new CoreEntityNotFoundException with error message and cause
     *
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CoreEntityNotFoundException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

    /**
     * Constructs a new CoreEntityNotFoundException with error message
     *
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     */
    public CoreEntityNotFoundException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new CoreEntityNotFoundException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CoreEntityNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CoreEntityNotFoundException
     */
    public CoreEntityNotFoundException() {
        super();
    }
}
