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
 * This exception is thrown in case of any internal database failures..
 */
public class ExternalCredentialMgmtServiceException extends ExternalCredentialMgmtException {

    private static final long serialVersionUID = -7299363403360632904L;

    /**
     * Constructs a new ExternalCredentialMgmtServiceException
     */
    public ExternalCredentialMgmtServiceException() {
        super();
    }

    /**
     * Constructs a new ExternalCredentialMgmtServiceException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ExternalCredentialMgmtServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new ExternalCredentialMgmtServiceException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCredentialMgmtServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExternalCredentialMgmtServiceException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCredentialMgmtServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
