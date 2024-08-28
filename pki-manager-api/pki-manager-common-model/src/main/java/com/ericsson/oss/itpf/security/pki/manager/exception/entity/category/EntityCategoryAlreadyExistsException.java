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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.category;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;

/**
 * This exception is thrown if the given Category already exists.
 */
public class EntityCategoryAlreadyExistsException extends EntityCategoryException {

    private static final long serialVersionUID = -9159478651454150562L;

    /**
     * Constructs a new EntityCategoryAlreadyExistsException
     */
    public EntityCategoryAlreadyExistsException() {
        super();
    }

    /**
     * Constructs a new EntityCategoryAlreadyExistsException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public EntityCategoryAlreadyExistsException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EntityCategoryAlreadyExistsException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityCategoryAlreadyExistsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EntityCategoryAlreadyExistsException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityCategoryAlreadyExistsException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
