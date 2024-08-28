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
 * Thrown to indicate there is already active certificate for the provided entity.
 * 
 */
public class CertificateAlreadyExistsException extends CertificateException {

    private static final long serialVersionUID = 6251727243298288430L;

    /**
     * Constructs a new CertificateAlreadyExistsException
     */
    public CertificateAlreadyExistsException() {
        super();
    }

    /**
     * Constructs a new CertificateAlreadyExistsException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateAlreadyExistsException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateAlreadyExistsException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateAlreadyExistsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateAlreadyExistsException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateAlreadyExistsException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
