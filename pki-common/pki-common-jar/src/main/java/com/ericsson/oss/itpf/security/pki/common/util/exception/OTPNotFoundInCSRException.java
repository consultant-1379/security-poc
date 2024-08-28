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
package com.ericsson.oss.itpf.security.pki.common.util.exception;

import javax.ejb.ApplicationException;

/**
 * Thrown to indicate there is no OTP found for the provided csr.
 * 
 */
@ApplicationException(rollback = true)
public class OTPNotFoundInCSRException extends RuntimeException {

    private static final long serialVersionUID = 6251727243298288430L;

    /**
     * Constructs a new OTPNotFoundInCSRException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public OTPNotFoundInCSRException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new OTPNotFoundInCSRException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public OTPNotFoundInCSRException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new OTPNotFoundInCSRException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public OTPNotFoundInCSRException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
