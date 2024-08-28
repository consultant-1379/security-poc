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
 * This exception is thrown if any message parsing error occurs
 * 
 * @author tcsramc
 * 
 */
public class MessageParsingException extends ProtocolException {

    private static final long serialVersionUID = -447527783572644534L;

    public MessageParsingException() {
        super();
    }

    /***
     * Creates an exception with the error message
     * 
     * @param message
     *            message to form an exception
     */
    public MessageParsingException(final String message) {
        super(message);
    }

    /**
     * Creates an exception with the error message and cause
     * 
     * @param message
     *            message to form exception
     * @param cause
     *            cause of the exception
     */
    public MessageParsingException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
