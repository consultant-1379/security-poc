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
 * Thrown to indicate Issuer of the given Entity Certificate is already revoked.
 * 
 * @author xbensar
 */

public class IssuerCertificateRevokedException extends RevocationException {

    private static final long serialVersionUID = 6072251101033851558L;

    /**
     * Constructs a new RevokedIssuerFoundException with detailed message
     *
     * @param errorMessage
     */
    public IssuerCertificateRevokedException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new RevokedIssuerFoundException with detailed cause
     *
     * @param cause
     */
    public IssuerCertificateRevokedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new RevokedIssuerFoundException with detailed message and cause
     *
     * @param errorMessage
     * @param cause
     */
    public IssuerCertificateRevokedException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
