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
 * This exception is thrown when there is an error in certificate revocation
 */
public class CertificateRevokedException extends CertificateException {

    private static final long serialVersionUID = -1385501683879392720L;

    /**
     * Constructs a new CertificateRevokedException
     */
    public CertificateRevokedException() {
        super();
    }

    /**
     * Constructs a new CertificateRevokedException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public CertificateRevokedException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateRevokedException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CertificateRevokedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CertificateRevokedException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CertificateRevokedException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
