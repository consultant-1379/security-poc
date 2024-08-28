/*
 *************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 **************************************************************
 */
package com.ericsson.oss.itpf.security.pki.common.util.exception;

/**
 * This Exception will be thrown when there is any conversion related errors during Certificate conversion.
 * 
 * @author xjagcho
 * 
 */

public class CertificateConversionException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = 3229863502814650729L;

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */

    public CertificateConversionException(final String message) {
        super(message);

    }

    /**
     * Creates an exception with a cause.
     * 
     * @param cause
     *            The cause of the exception.
     */

    public CertificateConversionException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates an exception with a message and a cause.
     * 
     * @param message
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */

    public CertificateConversionException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
