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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception;

/**
 * This exception is thrown whenever the certificate is not published
 * 
 * @author xdeemin
 *
 */
public class CertificateNotPublishedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new CertificateNotPublishedException
     */
    public CertificateNotPublishedException() {
        super();
    }

    /**
     * Constructs a new CertificateNotPublishedException with message
     * 
     * @param message
     *            The detailed message
     */
    public CertificateNotPublishedException(final String message) {
        super(message);

    }

    /**
     * Constructs a new CertificateNotPublishedException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public CertificateNotPublishedException(final String message, final Throwable cause) {
        super(message, cause);

    }

    /**
     * Constructs a new CertificateNotFoundException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public CertificateNotPublishedException(final Throwable cause) {
        super(cause);

    }

}
