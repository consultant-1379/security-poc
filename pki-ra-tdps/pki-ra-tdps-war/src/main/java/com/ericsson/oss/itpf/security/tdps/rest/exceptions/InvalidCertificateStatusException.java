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
package com.ericsson.oss.itpf.security.tdps.rest.exceptions;

/**
 * This is an exception class which will is thrown when the certificate status in the URL is invalid i.e anything other than ACTIVE/INACTIVE
 * 
 * @author tcsdemi
 *
 */
public class InvalidCertificateStatusException extends RuntimeException {

    private static final long serialVersionUID = 9144763665330905444L;

    /**
     * Constructs a new InvalidCertificateStatusException
     */
    public InvalidCertificateStatusException() {
        super();
    }

    /**
     * Constructs a new InvalidCertificateStatusException with message
     * 
     * @param message
     *            The detailed message
     */
    public InvalidCertificateStatusException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidCertificateStatusException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public InvalidCertificateStatusException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new InvalidCertificateStatusException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public InvalidCertificateStatusException(final Throwable cause) {
        super(cause);
    }
}
