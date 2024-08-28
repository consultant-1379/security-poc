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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity;

import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;

/**
 * This exception is parent of all CA related exceptions.
 */
public class CAEntityException extends EntityException {

    private static final long serialVersionUID = -4416351286767113642L;

    public CAEntityException() {
        super();
    }

    /**
     * Constructs a new CAEntityException with detailed message
     * 
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public CAEntityException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new CAEntityException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CAEntityException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CAEntityException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CAEntityException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
