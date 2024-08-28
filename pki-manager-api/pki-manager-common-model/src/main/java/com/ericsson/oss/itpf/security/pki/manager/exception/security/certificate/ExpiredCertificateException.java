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
 * ExpiredCertificateException is thrown when revocation/crl operations are requested for a expired certificate.
 */
public class ExpiredCertificateException extends CertificateException {

    private static final long serialVersionUID = -4926470741358358272L;

    /**
     * Constructs a new ExpiredCertificateException
     */
    public ExpiredCertificateException() {
        super();
    }

    /**
     * Constructs a new ExpiredCertificateException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ExpiredCertificateException(final String message) {
        super(message);
    }

    /**
     * Constructs a new ExpiredCertificateException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExpiredCertificateException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExpiredCertificateException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExpiredCertificateException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
