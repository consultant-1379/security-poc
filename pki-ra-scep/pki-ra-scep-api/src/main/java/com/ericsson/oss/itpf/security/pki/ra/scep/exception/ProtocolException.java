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
package com.ericsson.oss.itpf.security.pki.ra.scep.exception;

import javax.ejb.ApplicationException;

/**
 * ProtocolException is the super class for all the user defined exceptions.
 * 
 * @author xtelsow
 */
@ApplicationException(rollback = true)
public class ProtocolException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String message;

    /**
     * @return the message
     */

    public String getMessage() {
        return message;
    }

    /**
     * 
     * @param msg
     *            is description of the exception.
     */
    public ProtocolException(final String msg) {
        this.message = msg;
    }

    public ProtocolException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
        this.message = errorMessage;
    }
}