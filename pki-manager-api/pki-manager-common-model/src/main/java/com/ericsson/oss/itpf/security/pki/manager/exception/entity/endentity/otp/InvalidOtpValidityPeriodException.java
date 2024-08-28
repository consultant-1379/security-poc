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
package com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;

/**
 * This exception is thrown when OTP validity period is invalid.
 */
public class InvalidOtpValidityPeriodException extends OTPException {

    private static final long serialVersionUID = -4158305819467451513L;

    /**
     * Constructs a new InvalidOtpValidityPeriodException
     */
    public InvalidOtpValidityPeriodException() {
        super();
    }

    /**
     * Constructs a new InvalidOtpValidityPeriodException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidOtpValidityPeriodException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidOtpValidityPeriodException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidOtpValidityPeriodException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidOtpValidityPeriodException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidOtpValidityPeriodException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
