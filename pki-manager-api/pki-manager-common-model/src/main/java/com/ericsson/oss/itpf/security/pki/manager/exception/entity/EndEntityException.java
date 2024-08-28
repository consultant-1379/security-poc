/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 * 
 *  *
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
 * This Exception is the parent exception for all the entity related exceptions.
 */
public class EndEntityException extends EntityException {

    private static final long serialVersionUID = -3767684886375000912L;

    public EndEntityException() {
        super();
    }

    /**
     * Constructs a new EndEntityException with detailed message
     * 
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public EndEntityException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new EndEntityException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EndEntityException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new EndEntityException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public EndEntityException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
