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
package com.ericsson.oss.itpf.security.pki.core.exception.revocation;

import com.ericsson.oss.itpf.security.pki.core.exception.RevocationException;

/**
 * Thrown to indicate Issuer of the given Entity Certificate is already revoked.
 *
 * @author xbensar
 */
public class CertificatePathValidationException extends RevocationException {

    private static final long serialVersionUID = 6072251101033851558L;

    /**
     * Constructs a new CertificatePathValidationException with detailed message
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificatePathValidationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new CertificatePathValidationException with detailed cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificatePathValidationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificatePathValidationException with detailed message and cause
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificatePathValidationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
