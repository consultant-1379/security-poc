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

package com.ericsson.oss.itpf.security.kaps.common.exception;

/**
 * This exception will be thrown when signing content is failed.
 */
public class SignatureException extends RuntimeException {

    private static final long serialVersionUID = -5815868892844682718L;

    /**
     * Constructs a new SignatureException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public SignatureException(final String message) {
        super(message);
    }

    /**
     * Constructs a new SignatureException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public SignatureException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new SignatureException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public SignatureException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
