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
 * This exception is thrown when the given entity is not valid.
 */
public class InvalidEntityException extends EntityException {

    private static final long serialVersionUID = -5850550132032838771L;

    /**
     * Constructs a new InvalidEntityException
     */
    public InvalidEntityException() {
        super();
    }

    /**
     * Constructs a new InvalidEntityException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public InvalidEntityException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidEntityException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public InvalidEntityException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidEntityException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public InvalidEntityException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
