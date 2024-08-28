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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator;

/**
 * Thrown to indicate exception while performing IAK validation.
 * 
 * @author
 * 
 */
public class IAKValidationException extends RuntimeException {

    private static final long serialVersionUID = -8624695821803772346L;

    /**
     * Creates an empty exception.
     */
    public IAKValidationException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */
    public IAKValidationException(final String message) {
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

    public IAKValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
