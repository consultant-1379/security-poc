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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;

/**
 * This exception is thrown when the certificate version is unsupported.
 */
public class UnSupportedCertificateVersion extends CertificateFieldException {

    private static final long serialVersionUID = -7002975826746004529L;

    /**
     * Constructs a new UnSupportedCertificateVersion
     */
    public UnSupportedCertificateVersion() {
        super();
    }

    /**
     * Constructs a new UnSupportedCertificateVersion with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public UnSupportedCertificateVersion(final String message) {
        super(message);
    }

    /**
     * Constructs a new UnSupportedCertificateVersion with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public UnSupportedCertificateVersion(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new UnSupportedCertificateVersion with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public UnSupportedCertificateVersion(final String message, final Throwable cause) {
        super(message, cause);
    }

}
