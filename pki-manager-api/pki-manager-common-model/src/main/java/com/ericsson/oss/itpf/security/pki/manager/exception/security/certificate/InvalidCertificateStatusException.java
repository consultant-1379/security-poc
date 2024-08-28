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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;

/**
 * This exception is thrown to indicate that the given CertificateStatus is not valid.
 */
public class InvalidCertificateStatusException extends CertificateException {

    private static final long serialVersionUID = -1161153254510955531L;

    /**
     * Constructs a new InvalidCertificateStatusException
     */
    public InvalidCertificateStatusException() {
        super();
    }

    /**
     * Constructs a new InvalidCertificateStatusException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidCertificateStatusException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidCertificateStatusException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCertificateStatusException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCertificateStatusException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCertificateStatusException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
