/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.crl.exception;

import com.ericsson.oss.itpf.security.kaps.exception.CRLException;


/**
 * This exception is thrown when CRL extensions are invalid.
 * 
 * @author xramcho
 * 
 */
public class InvalidCRLExtensionsException extends CRLException {

    private static final long serialVersionUID = -2852989397294141294L;

    /**
     * Constructs a new InvalidCRLExtensionsException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidCRLExtensionsException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidCRLExtensionsException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLExtensionsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCRLExtensionsException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLExtensionsException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
