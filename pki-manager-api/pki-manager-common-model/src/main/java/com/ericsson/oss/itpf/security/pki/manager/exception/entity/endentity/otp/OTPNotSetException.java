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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;

/**
 * This exception is thrown when the OTP is not set.
 */
public class OTPNotSetException extends OTPException {

    private static final long serialVersionUID = 2480130087953536701L;

    /**
     * Constructs a new OTPNotSetException
     */
    public OTPNotSetException() {
        super();
    }

    /**
     * Constructs a new OTPNotSetException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public OTPNotSetException(final String message) {
        super(message);
    }

    /**
     * Constructs a new OTPNotSetException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public OTPNotSetException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new OTPNotSetException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public OTPNotSetException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
