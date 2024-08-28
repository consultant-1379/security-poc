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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.exception;
/*
 * This exception is thrown for any validation failures. 
 */
public class ValidationServiceException extends RuntimeException {

    /**
     * 
     */
    private static final long serialVersionUID = 817767378411028163L;

    public ValidationServiceException() {
        super();
    }

    /**
     * Creates an exception with the error message
     * 
     * @param message
     *            Message to form an exception
     */
    public ValidationServiceException(final String message) {
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
    public ValidationServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
