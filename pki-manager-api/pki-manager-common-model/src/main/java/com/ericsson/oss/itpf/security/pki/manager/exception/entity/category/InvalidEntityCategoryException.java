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
 * 
 * This exception is thrown to indicate that category name is in invalid format.
 * 
 */
public class InvalidEntityCategoryException extends EntityCategoryException {

    private static final long serialVersionUID = -9203806835232994127L;

    /**
     * Constructs a new InvalidEntityCategoryException
     */
    public InvalidEntityCategoryException() {
        super();
    }

    /**
     * Constructs a new InvalidEntityCategoryException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidEntityCategoryException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidEntityCategoryException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidEntityCategoryException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidEntityCategoryException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidEntityCategoryException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
