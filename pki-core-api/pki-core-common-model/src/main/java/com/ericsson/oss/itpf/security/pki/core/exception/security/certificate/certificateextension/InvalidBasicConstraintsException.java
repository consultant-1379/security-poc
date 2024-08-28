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
 * This exception is thrown when BasicConstraints in certificate extensions is not valid.
 * 
 */
public class InvalidBasicConstraintsException extends InvalidCertificateExtensionsException {

    private static final long serialVersionUID = -2247925807305886774L;

    /**
     * Constructs a new InvalidBasicConstraintsException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidBasicConstraintsException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidBasicConstraintsException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidBasicConstraintsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidBasicConstraintsException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidBasicConstraintsException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
