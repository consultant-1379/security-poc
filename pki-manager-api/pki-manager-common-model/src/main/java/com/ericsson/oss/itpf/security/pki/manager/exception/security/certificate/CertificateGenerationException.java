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
 * This exception is thrown to indicate that an exception has occurred during certificate generation
 */
public class CertificateGenerationException extends CertificateException {

    private static final long serialVersionUID = 358894277239527218L;

    /**
     * Constructs a new CertificateGenerationException
     */
    public CertificateGenerationException() {
        super();
    }

    /**
     * Constructs a new CertificateGenerationException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateGenerationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateGenerationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateGenerationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateGenerationException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateGenerationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
