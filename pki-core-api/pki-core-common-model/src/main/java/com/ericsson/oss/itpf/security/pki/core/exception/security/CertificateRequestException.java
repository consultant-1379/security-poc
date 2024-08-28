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
package com.ericsson.oss.itpf.security.pki.core.exception.security;

import com.ericsson.oss.itpf.security.pki.core.exception.CoreSecurityException;

/**
 * Base exception for all certificate request related exceptions.
 *
 * @author tcsrrch
 *
 */
public class CertificateRequestException extends CoreSecurityException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a CertificateRequestException
     */
    public CertificateRequestException() {
        super();
    }

    /**
     * Constructs a new CertificateRequestException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     *
     */
    public CertificateRequestException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateRequestException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateRequestException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateRequestException with detailed message and cause
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateRequestException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
