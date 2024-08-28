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
package com.ericsson.oss.itpf.security.pki.common.util.exception;

/**
 * is thrown if certificate is null
 * 
 * @author tcsramc
 * 
 */
public class CertificateIsNullException extends RuntimeException {

    private static final long serialVersionUID = 4161359067064138174L;

    public CertificateIsNullException() {
        super();
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     */
    public CertificateIsNullException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */
    public CertificateIsNullException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
