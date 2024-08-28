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
package com.ericsson.oss.itpf.security.kaps.exception;


/**
 * This exception is base exception for certificate exceptions.
 */
public class CertificateException extends KAPSRuntimeException {

    private static final long serialVersionUID = 482007842369632761L;

    /**
     * Constructs a new CertificateException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
