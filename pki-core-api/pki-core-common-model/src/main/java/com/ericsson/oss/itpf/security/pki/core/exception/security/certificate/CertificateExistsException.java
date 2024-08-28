/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
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
 * This exception is thrown to indicate an Active Certificate exists for the given entity
 */
public class CertificateExistsException extends CertificateException {

    private static final long serialVersionUID = -6463743178277943035L;

    /**
     * Constructs a new CertificateExistsException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateExistsException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateExistsException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateExistsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateExistsException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateExistsException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
