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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;

/**
 * This exception is thrown when the CSR is already present in the PKI Manager.
 * 
 */

public class CSRExistsException extends CertificateException {

    private static final long serialVersionUID = 6235223800847425359L;

    /**
     * Constructs a new CSRExistsException with detailed message
     * 
     * @param message
     * 
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CSRExistsException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CSRExistsException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CSRExistsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CSRExistsException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CSRExistsException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
