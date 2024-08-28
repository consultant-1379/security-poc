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
package com.ericsson.oss.itpf.security.pki.common.keystore.exception;

/**
 * This Exception will be thrown when Certificate Chain not found in the Key Store.
 * 
 * @author xkarlak
 */
public class CertificateChainNotFoundException extends KeyStoreFileReaderException {

    /**
     *
     */
    private static final long serialVersionUID = 7717834839272088221L;

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */

    public CertificateChainNotFoundException(final String message) {
        super(message);

    }

    /**
     * Creates an exception with a cause.
     * 
     * @param cause
     *            The cause of the exception.
     */

    public CertificateChainNotFoundException(final Throwable cause) {
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

    public CertificateChainNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
