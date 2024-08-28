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

import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;

/**
 * This exception is thrown when unsupported request comes
 * 
 * @author tcsramc
 * 
 */
public class UnsupportedRequestTypeException extends ValidationException {

    private static final long serialVersionUID = -7496037882265432557L;

    /**
     * Creates an exception with the message
     * 
     * @param message
     *            message to form exception
     */
    public UnsupportedRequestTypeException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Creates an exception with the message and cause
     * 
     * @param message
     *            message to form exception
     * @param cause
     *            cause of the exception
     */
    public UnsupportedRequestTypeException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
