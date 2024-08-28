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
 * This Exception is thrown when deleting an entity that has active certificates.
 *
 */
public class CoreEntityInUseException extends CoreEntityException {

    private static final long serialVersionUID = 1L;

    /**
     *
     * Constructs a new CoreEntityInUseException with detailed message and cause
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CoreEntityInUseException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

    /**
     * Constructs a new CoreEntityInUseException with detailed message
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CoreEntityInUseException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new CoreEntityInUseException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CoreEntityInUseException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CoreEntityInUseException
     */
    public CoreEntityInUseException() {
        super();
    }
}
