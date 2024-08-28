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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception;

/**
 * This Exception is thrown when the revocation the given certificate fails.
 * 
 * @author tcsramc
 *
 */
public class RevocationResponseBuilderException extends RuntimeException {

    private static final long serialVersionUID = 921947814720265601L;

    public RevocationResponseBuilderException() {
        super();
    }

    /**
     * Creates an exception with the error message
     * 
     * @param message
     *            Message to form an exception
     */
    public RevocationResponseBuilderException(final String message) {
        super(message);
    }

    /**
     * Creates an exception with the message
     * 
     * @param message
     *            Error message to form exception
     * @param cause
     *            cause of the exception
     */
    public RevocationResponseBuilderException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
