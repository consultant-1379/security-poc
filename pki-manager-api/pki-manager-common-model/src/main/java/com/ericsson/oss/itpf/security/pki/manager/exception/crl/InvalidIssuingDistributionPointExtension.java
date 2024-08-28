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
package com.ericsson.oss.itpf.security.pki.manager.exception.crl;


/**
 * This exception is thrown if the IssuingDistibutionPoint Extension is invalid.
 * 
 * @author tcsanne
 *
 */
public class InvalidIssuingDistributionPointExtension extends CRLExtensionException {
    private static final long serialVersionUID = -1137335064131487259L;

    /**
     * Constructs a new InvalidIssuingDistributionPointExtension with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidIssuingDistributionPointExtension(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidIssuingDistributionPointExtension with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidIssuingDistributionPointExtension(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidIssuingDistributionPointExtension with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidIssuingDistributionPointExtension(final String message, final Throwable cause) {
        super(message, cause);
    }
}
