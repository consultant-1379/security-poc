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
package com.ericsson.oss.itpf.security.pki.common.cmp.model.exception;

import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This exception is thrown when any error occurs in signing
 * 
 * @author tcsramc
 * 
 */
public class ResponseSignerException extends ProtocolException {

    private static final long serialVersionUID = 6591993098971783866L;

    public ResponseSignerException() {
        super();
    }

    /**
     * Creates an exception with the message
     * 
     * @param message
     *            message to form exception
     */
    public ResponseSignerException(final String message) {
        super(message);
    }

    /**
     * Creates an exception with the message and cause
     * 
     * @param message
     *            message to form exception
     * @param cause
     *            cause of the exception
     */
    public ResponseSignerException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
