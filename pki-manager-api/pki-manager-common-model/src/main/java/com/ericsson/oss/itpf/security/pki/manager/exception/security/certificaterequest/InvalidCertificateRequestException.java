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
 * This exception is thrown to indicate that the given Certificate Request is invalid.
 * <ul>
 * <li>If in case CertificateRequest signature is not valid.</li>
 * <li>Parameters passed in the CertificateRequest request are not valid this exception is thrown.</li>
 * </ul>
 * 
 */
public class InvalidCertificateRequestException extends CertificateRequestException {

    private static final long serialVersionUID = -3308049022301715892L;

    /**
     * Constructs a new InvalidCertificateRequestException
     */
    public InvalidCertificateRequestException() {
        super();
    }

    /**
     * Constructs a new InvalidCertificateRequestException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidCertificateRequestException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new InvalidCertificateRequestException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCertificateRequestException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCertificateRequestException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCertificateRequestException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
