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
 * This exception is thrown when the invalid extended key usage is provided as part of the request.
 */
public class InvalidExtendedKeyUsageExtension extends CertificateExtensionException {

    private static final long serialVersionUID = 4391694981545203270L;

    /**
     * Constructs a new InvalidExtendedKeyUsageExtension
     */
    public InvalidExtendedKeyUsageExtension() {
        super();
    }

    /**
     * Constructs a new InvalidExtendedKeyUsageExtension with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidExtendedKeyUsageExtension(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidExtendedKeyUsageExtension with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidExtendedKeyUsageExtension(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidExtendedKeyUsageExtension with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidExtendedKeyUsageExtension(final String message, final Throwable cause) {
        super(message, cause);
    }

}
