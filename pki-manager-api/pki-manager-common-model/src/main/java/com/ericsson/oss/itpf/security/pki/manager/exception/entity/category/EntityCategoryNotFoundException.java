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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.category;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;

/**
 * This exception is thrown to indicate category is not found.
 */
public class EntityCategoryNotFoundException extends EntityCategoryException {

    private static final long serialVersionUID = -7540395938243348504L;

    /**
     * Constructs a new EntityCategoryNotFoundException
     */

    public EntityCategoryNotFoundException() {
        super();
    }

    /**
     * Constructs a new EntityCategoryNotFoundException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public EntityCategoryNotFoundException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EntityCategoryNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityCategoryNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EntityCategoryNotFoundException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EntityCategoryNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
