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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;

/**
 * This exception is thrown to indicate that certificates are not present for the corresponding entity.
 * 
 */
public class CertificateNotFoundException extends CertificateException {

    private static final long serialVersionUID = 6251727243298288430L;

    /**
     * Constructs a new CertificateNotFoundException
     */
    public CertificateNotFoundException() {
        super();
    }

    /**
     * Constructs a new CertificateNotFoundException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateNotFoundException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateNotFoundException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
