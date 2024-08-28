/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 * 
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt;

import com.ericsson.oss.itpf.security.pki.manager.exception.ExternalCredentialMgmtException;

/**
 * This exception is thrown to indicate that an exception has occurred during CRL generation.
 */
public class ExternalCRLException extends ExternalCredentialMgmtException {

    private static final long serialVersionUID = -7299363403360632904L;

    /**
     * Constructs a new ExternalCRLException.
     */
    public ExternalCRLException() {
        super();
    }

    /**
     * Constructs a new ExternalCRLException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ExternalCRLException(final String message) {
        super(message);
    }

    /**
     * Constructs a new ExternalCRLException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCRLException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExternalCRLException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCRLException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
