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
 * This Exception is thrown when an invalid attribute is present in the entity.
 *
 * @author tcsrrch
 *
 */
public class InvalidCoreEntityAttributeException extends CoreEntityException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new InvalidCoreEntityAttributeException
     */
    public InvalidCoreEntityAttributeException() {
        super();
    }

    /**
     * Constructs a new InvalidCoreEntityAttributeException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     *
     */
    public InvalidCoreEntityAttributeException(final String message) {
        super(message);
    }

    /**
     *
     * Constructs a new InvalidCoreEntityAttributeException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCoreEntityAttributeException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCoreEntityAttributeException with message and cause
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCoreEntityAttributeException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
