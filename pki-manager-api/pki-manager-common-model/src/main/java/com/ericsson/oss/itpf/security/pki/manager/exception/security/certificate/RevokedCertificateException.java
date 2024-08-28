/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;

/**
 * RevokedCertificateException is thrown when revocation/crl operations are requested for a revoked certificate.
 */
public class RevokedCertificateException extends CertificateException {

    private static final long serialVersionUID = 1938696951848932621L;

    /**
     * Constructs a new RevokedCertificateException
     */
    public RevokedCertificateException() {
        super();
    }

    /**
     * Constructs a new RevokedCertificateException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public RevokedCertificateException(final String message) {
        super(message);
    }

    /**
     * Constructs a new RevokedCertificateException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public RevokedCertificateException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new RevokedCertificateException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public RevokedCertificateException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
