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
package com.ericsson.oss.itpf.security.pki.manager.common.exception;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * This exception is thrown when CertificateStatus update has failed.
 */
public class CertificateStatusUpdateFailedException extends CertificateServiceException {

    private static final long serialVersionUID = 482007842369632761L;

    /**
     * Constructs a new CertificateStatusUpdateFailedException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CertificateStatusUpdateFailedException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateStatusUpdateFailedException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateStatusUpdateFailedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateStatusUpdateFailedException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CertificateStatusUpdateFailedException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
