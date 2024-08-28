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

import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;

/**
 * This exception is thrown when the exceptions related to entity service occurs.
 */
public class EntityServiceException extends EntityException {

    private static final long serialVersionUID = 606091876144316227L;

    /**
     * Constructs a new EntityServiceException
     */
    public EntityServiceException() {
        super();
    }

    /**
     * Constructs a new EntityServiceException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public EntityServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EntityServiceException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EntityServiceException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
