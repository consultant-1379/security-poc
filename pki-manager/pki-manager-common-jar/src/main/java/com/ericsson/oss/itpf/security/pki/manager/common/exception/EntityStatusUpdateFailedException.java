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
package com.ericsson.oss.itpf.security.pki.manager.common.exception;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;


/**
 * This exception is thrown when EntityStatus update has failed.
 */
public class EntityStatusUpdateFailedException extends EntityServiceException{

    private static final long serialVersionUID = -9080662759558132480L;

    /**
     * Constructs a new EntityStatusUpdateFailedException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public EntityStatusUpdateFailedException(final String message) {
        super(message);
    }

    /**
     * Constructs a new EntityStatusUpdateFailedException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityStatusUpdateFailedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EntityStatusUpdateFailedException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public EntityStatusUpdateFailedException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
