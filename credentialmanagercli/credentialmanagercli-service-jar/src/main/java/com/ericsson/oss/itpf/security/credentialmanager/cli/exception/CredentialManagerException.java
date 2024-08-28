/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.exception;

public class CredentialManagerException extends RuntimeException {

    /**
     * 
     */
    private static final long serialVersionUID = 4366229431047402915L;

    /**
     * 
     */
    public CredentialManagerException() {
        // ??
    }

    /**
     * @param message
     */
    public CredentialManagerException(final String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public CredentialManagerException(final Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public CredentialManagerException(final String message,
            final Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public CredentialManagerException(final String message,
            final Throwable cause, final boolean enableSuppression,
            final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
