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
 * This exception is thrown to indicate Root CA cannot be revoked.
 * 
 * @author xbensar
 */

public class RootCertificateRevocationException extends RevocationException {

    private static final long serialVersionUID = -6975842669528448523L;

    /**
     * Constructs a new RootCertificateRevocationException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public RootCertificateRevocationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new RootCertificateRevocationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public RootCertificateRevocationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new RootCertificateRevocationException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public RootCertificateRevocationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
