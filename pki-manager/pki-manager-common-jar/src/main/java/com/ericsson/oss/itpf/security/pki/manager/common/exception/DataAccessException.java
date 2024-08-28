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
package com.ericsson.oss.itpf.security.pki.manager.common.exception;

import javax.ejb.ApplicationException;

/**
 * Thrown to indicate exception while performing database operations.
 * 
 * @author xprabil
 * 
 */
@ApplicationException(rollback = true)
public class DataAccessException extends RuntimeException {

    private static final long serialVersionUID = -2270808839596667616L;

    /**
     * Creates an empty exception.
     */
    public DataAccessException() {

        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */
    public DataAccessException(final String message) {

        super(message);
    }

    /**
     * Creates an exception with a cause.
     * 
     * @param cause
     *            The cause of the exception.
     */
    public DataAccessException(final Throwable cause) {

        super(cause);
    }

    /**
     * Creates an exception with a message and a cause.
     * 
     * @param message
     *            The message describing the error, NOT cause.getMessage()!
     * @param cause
     *            The cause of the exception.
     */
    public DataAccessException(final String message, final Throwable cause) {

        super(message, cause);
    }
}
