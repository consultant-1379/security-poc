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
 * This exception is thrown when CRLNumber Extension is invalid.
 *
 * @author xbensar
 */

public class InvalidCRLNumberExtension extends CRLExtensionException {

    private static final long serialVersionUID = -1137335064131487259L;

    /**
     * Constructs a new InvalidCRLNumberExtension with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidCRLNumberExtension(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidCRLNumberExtension with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLNumberExtension(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCRLNumberExtension with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLNumberExtension(final String message, final Throwable cause) {
        super(message, cause);
    }
}
