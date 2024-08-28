/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 * 
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;

/**
 * This exception is thrown when the invalid basic constraints is provided as part of the request.
 */
public class InvalidBasicConstraintsExtension extends CertificateExtensionException {

    private static final long serialVersionUID = -6777752900953850574L;

    /**
     * Constructs a new InvalidBasicConstraintsExtension
     */
    public InvalidBasicConstraintsExtension() {
        super();
    }

    /**
     * Constructs a new InvalidBasicConstraintsExtension with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidBasicConstraintsExtension(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidBasicConstraintsExtension with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidBasicConstraintsExtension(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidBasicConstraintsExtension with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidBasicConstraintsExtension(final String message, final Throwable cause) {
        super(message, cause);
    }

}
