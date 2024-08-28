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
package com.ericsson.oss.itpf.security.pki.manager.exception.revocation;

import com.ericsson.oss.itpf.security.pki.manager.exception.RevocationException;

/**
 * This exception is thrown to indicate that the requested Certificate issuer is not found.
 * 
 * @author xvambur
 */

public class IssuerNotFoundException extends RevocationException {

    private static final long serialVersionUID = -5425152746842310718L;

    /**
     * Constructs a new IssuerNotFoundException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public IssuerNotFoundException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new IssuerNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public IssuerNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new IssuerNotFoundException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public IssuerNotFoundException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}