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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity;

import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;

/**
 * This Exception is thrown when deleting an entity that is already deleted.
 */
public class EntityAlreadyDeletedException extends EntityException {

    private static final long serialVersionUID = 3060152457914977646L;

    public EntityAlreadyDeletedException() {
        super();
    }

    /**
     * Constructs a new EntityAlreadyDeletedException with detailed message
     * 
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public EntityAlreadyDeletedException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new EntityAlreadyDeletedException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EntityAlreadyDeletedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EntityAlreadyDeletedException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EntityAlreadyDeletedException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}