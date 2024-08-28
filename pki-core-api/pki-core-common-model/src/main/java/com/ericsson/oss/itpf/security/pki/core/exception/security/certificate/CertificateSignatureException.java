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
package com.ericsson.oss.itpf.security.pki.core.exception.security.certificate;

import com.ericsson.oss.itpf.security.pki.core.exception.security.CertificateException;

/**
 * This exception is thrown to indicate that Certificate signing has failed during Certificate generation
 */
public class CertificateSignatureException extends CertificateException {

    private static final long serialVersionUID = -2242284821985443458L;

    /**
     * Constructs a CertificateSignatureException
     */
    public CertificateSignatureException() {
        super();
    }

    /**
     * Constructs a new CertificateSignatureException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateSignatureException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateSignatureException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateSignatureException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateSignatureException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateSignatureException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
