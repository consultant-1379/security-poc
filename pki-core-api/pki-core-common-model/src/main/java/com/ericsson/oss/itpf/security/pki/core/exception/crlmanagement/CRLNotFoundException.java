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
package com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement;

import com.ericsson.oss.itpf.security.pki.core.exception.CRLException;

/**
 * CRLNotFoundException is thrown, if CRL is not found for a requested Certificate Authority.
 *
 * @author xramdag
 *
 */
public class CRLNotFoundException extends CRLException {

    private static final long serialVersionUID = 5977714506110254948L;

    /**
     * Constructs a new CRLNotFoundException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CRLNotFoundException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CRLNotFoundException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CRLNotFoundException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
