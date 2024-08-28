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
 * This Exception is thrown when the given CSR in the Request message is not valid.
 * 
 */
public class ResponseEventBuilderException extends RuntimeException {

    private static final long serialVersionUID = -2981740507295399326L;

    public ResponseEventBuilderException() {
        super();
    }

    /**
     * Creates an exception with the error message
     * 
     * @param message
     *            Message to form an exception
     */
    public ResponseEventBuilderException(final String message) {
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
    public ResponseEventBuilderException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
