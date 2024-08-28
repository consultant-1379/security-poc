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
 *
 * This exception is thrown to indicate {@link Certificate} field validation is failed in PKI-Core.
 *
 * @author tcsrrch
 *
 */
public class CertificateFieldException extends CertificateException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new CertificateFieldException
     */
    public CertificateFieldException() {
        super();
    }

    /**
     * Constructs a new CertificateFieldException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateFieldException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateFieldException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateFieldException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateFieldException with detailed message and cause
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateFieldException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
