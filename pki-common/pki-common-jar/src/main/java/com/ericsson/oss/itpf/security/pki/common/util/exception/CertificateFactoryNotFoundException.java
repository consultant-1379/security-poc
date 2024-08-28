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

public class CertificateFactoryNotFoundException extends RuntimeException {

    private static final long serialVersionUID = -6416450381767135952L;

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */

    public CertificateFactoryNotFoundException(final String message) {
        super(message);

    }

    /**
     * Creates an exception with a cause.
     * 
     * @param cause
     *            The cause of the exception.
     */

    public CertificateFactoryNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates an exception with a message and a cause.
     * 
     * @param message
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */

    public CertificateFactoryNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
