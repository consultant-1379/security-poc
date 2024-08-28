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
 * This exception is thrown to indicate that an exception has occured during certificate generation
 */
public class CertificateGenerationException extends CertificateException {

    private static final long serialVersionUID = 2679545734455867404L;


    /**
     *Constructs a new CertificateGenerationException
     */
    public CertificateGenerationException() {
        super();
    }


    /**
     * Constructs a new CertificateGenerationException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
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
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateGenerationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
