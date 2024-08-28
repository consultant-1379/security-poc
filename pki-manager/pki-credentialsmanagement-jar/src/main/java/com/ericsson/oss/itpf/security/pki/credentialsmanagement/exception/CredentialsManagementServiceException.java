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
package com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception;

import javax.ejb.ApplicationException;

/**
 * Thrown to indicate the internal service exception in credential management
 * 
 * @author tcsnapa
 * 
 */
@ApplicationException(rollback = true)
public class CredentialsManagementServiceException extends RuntimeException {

    private static final long serialVersionUID = -8624695821803772346L;

    /**
     * Creates an empty exception.
     */
    public CredentialsManagementServiceException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */
    public CredentialsManagementServiceException(final String message) {
        super(message);
    }

    /**
     * Creates an exception with a message and cause.
     * 
     * @param message
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */

    public CredentialsManagementServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
