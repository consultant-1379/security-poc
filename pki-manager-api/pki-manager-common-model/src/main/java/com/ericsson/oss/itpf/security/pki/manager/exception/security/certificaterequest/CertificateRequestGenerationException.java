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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateRequestException;

/**
 * This exception is thrown when CertificateRequest generation or export is failed.
 */
public class CertificateRequestGenerationException extends CertificateRequestException {

    private static final long serialVersionUID = 2277894613797141736L;

    /**
     * Constructs a new CertificateRequestGenerationException
     */
    public CertificateRequestGenerationException() {
        super();
    }

    /**
     * Constructs a new CertificateRequestGenerationException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateRequestGenerationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateRequestGenerationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateRequestGenerationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateRequestGenerationException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateRequestGenerationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
