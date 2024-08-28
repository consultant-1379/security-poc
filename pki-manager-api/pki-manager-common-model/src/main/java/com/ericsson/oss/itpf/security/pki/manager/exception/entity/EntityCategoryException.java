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
 * This exception is the parent of all the entity category related exceptions.
 */
public class EntityCategoryException extends EntityException {

    private static final long serialVersionUID = 571652391481145436L;

    /**
     * Constructs a new EntityCategoryException
     */
    public EntityCategoryException() {
        super();
    }

    /**
     * Constructs a new EntityCategoryException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public EntityCategoryException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EntityCategoryException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EntityCategoryException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EntityCategoryException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EntityCategoryException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
