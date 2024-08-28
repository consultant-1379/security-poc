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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;

/**
 * @author tcsprma
 * 
 *         This exception is thrown when the invalid CRL distribution point is provided as part of request.
 */
public class InvalidCRLDistributionPointsExtension extends CertificateExtensionException {

    private static final long serialVersionUID = -6873489405754362401L;

    /**
     * Constructs a new InvalidAuthorityKeyIdentifierExtension
     */
    public InvalidCRLDistributionPointsExtension() {
        super();
    }

    /**
     * Constructs a new InvalidAuthorityKeyIdentifierExtension with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidCRLDistributionPointsExtension(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidAuthorityKeyIdentifierExtension with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLDistributionPointsExtension(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidAuthorityKeyIdentifierExtension with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLDistributionPointsExtension(final String message, final Throwable cause) {
        super(message, cause);
    }

}
