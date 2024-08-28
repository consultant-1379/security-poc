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
package com.ericsson.oss.itpf.security.credmservice.exceptions;

public class CredentialManagerStartupException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     *
     */
    public CredentialManagerStartupException() {
        super();
    }

    /**
     * @param message
     * @param cause
     */
    public CredentialManagerStartupException(final String message, final Throwable cause) {
        super("credential-manager-service: CredentialManagerStartupException: " + message, cause);
    }

    /**
     * @param message
     */
    public CredentialManagerStartupException(final String message) {
        super("credential-manager-service: CredentialManagerStartupException: " + message);
    }

    /**
     * @param cause
     */
    public CredentialManagerStartupException(final Throwable cause) {
        super(cause);
    }

}
