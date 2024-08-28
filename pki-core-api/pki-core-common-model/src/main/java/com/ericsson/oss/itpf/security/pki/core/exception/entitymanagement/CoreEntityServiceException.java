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
 * This Exception is thrown for any entity related database errors in PKI Core.
 *
 */
public class CoreEntityServiceException extends CoreEntityException {

    private static final long serialVersionUID = -6642523010310839450L;

    /**
     *
     * Constructs a new CoreEntityServiceException with detailed message and cause
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CoreEntityServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

    /**
     * Constructs a new CoreEntityServiceException with detailed message
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CoreEntityServiceException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new CoreEntityServiceException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     *
     */
    public CoreEntityServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CoreEntityServiceException
     */
    public CoreEntityServiceException() {
        super();
    }

}