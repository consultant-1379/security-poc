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
package com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension;

import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;

/**
 * This exception is thrown when KeyUsage in certificate extensions is not valid.
 * 
 */
public class InvalidKeyUsageException extends InvalidCertificateExtensionsException {

    private static final long serialVersionUID = -4921330184372440770L;

    /**
     * Constructs a new InvalidKeyUsageException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidKeyUsageException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidKeyUsageException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidKeyUsageException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidKeyUsageException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidKeyUsageException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
