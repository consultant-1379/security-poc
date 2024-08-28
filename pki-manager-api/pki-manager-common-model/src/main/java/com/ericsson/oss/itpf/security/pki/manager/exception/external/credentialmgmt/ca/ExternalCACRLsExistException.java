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
package com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca;

import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCAException;

/**
 * Thrown to indicate external CA is used in a Trust Profile.
 *
 */
public class ExternalCACRLsExistException extends ExternalCAException {

    private static final long serialVersionUID = 6072251101033851558L;

    /**
     * Constructs a new ExternalCACRLsExistException
     */
    public ExternalCACRLsExistException() {
        super();
    }

    /**
     * Constructs a new ExternalCACRLsExistException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ExternalCACRLsExistException(final String message) {
        super(message);
    }

    /**
     * Constructs a new ExternalCACRLsExistException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCACRLsExistException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExternalCACRLsExistException with detailed message and cause
     *
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCACRLsExistException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
