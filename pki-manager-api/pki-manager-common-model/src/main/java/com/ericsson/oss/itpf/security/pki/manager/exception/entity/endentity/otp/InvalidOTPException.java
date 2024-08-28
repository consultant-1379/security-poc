/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;

/**
 * This exception is thrown when invalid OTP is provided.
 */
public class InvalidOTPException extends OTPException {


    private static final long serialVersionUID = 2480130087953536701L;

    /**
     * Constructs a new InvalidOTPException
     */
    public InvalidOTPException() {
        super();
    }

    /**
     * Constructs a new InvalidOTPException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidOTPException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidOTPException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidOTPException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidOTPException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidOTPException(final String message, final Throwable cause) {
        super(message, cause);
    }



}
