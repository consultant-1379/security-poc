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
package com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield;

import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateFieldException;

/**
 * This exception is thrown when the Certificate version is not supported
 *
 */
public class UnsupportedCertificateVersionException extends CertificateFieldException {

    private static final long serialVersionUID = 8108433228885140702L;

    /**
     * Constructs a new UnsupportedCertificateVersionException
     */
    public UnsupportedCertificateVersionException() {
        super();
    }

    /**
     * Constructs a new UnsupportedCertificateVersionException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public UnsupportedCertificateVersionException(final String message) {
        super(message);
    }

    /**
     * Constructs a new UnsupportedCertificateVersionException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public UnsupportedCertificateVersionException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new UnsupportedCertificateVersionException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public UnsupportedCertificateVersionException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
