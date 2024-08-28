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
package com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt;

import com.ericsson.oss.itpf.security.pki.manager.exception.ExternalCredentialMgmtException;

/**
 * This exception is thrown when there is an error with External CA
 */
public class ExternalCAException extends ExternalCredentialMgmtException {

    private static final long serialVersionUID = -7299363403360632904L;

    /**
     * Constructs a new ExternalCAException
     */
    public ExternalCAException() {
        super();
    }

    /**
     * Constructs a new ExternalCAException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ExternalCAException(final String message) {
        super(message);
    }

    /**
     * Constructs a new ExternalCAException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCAException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExternalCAException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCAException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
