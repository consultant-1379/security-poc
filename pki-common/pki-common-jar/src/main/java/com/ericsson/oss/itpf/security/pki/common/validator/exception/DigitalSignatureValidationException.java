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
package com.ericsson.oss.itpf.security.pki.common.validator.exception;

import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;

/**
 * This exception is thrown when digital signature validation fails.
 * 
 * @author tcsramc
 * 
 */
public class DigitalSignatureValidationException extends ValidationException {

    private static final long serialVersionUID = -7170649263081548740L;

    public DigitalSignatureValidationException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     */
    public DigitalSignatureValidationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */
    public DigitalSignatureValidationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

    /**
     * Creates an exception with a message.
     * 
     * @param cause
     *            The cause of the exception.
     */
    public DigitalSignatureValidationException(final Throwable cause) {
        super(cause);
    }
}
