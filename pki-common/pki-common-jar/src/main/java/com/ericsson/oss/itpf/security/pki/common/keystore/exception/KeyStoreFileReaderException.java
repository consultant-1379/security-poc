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
 * This Exception super class for all the user defined exceptions which will be thrown when there is any exception while loading and reading files from KeyStore file.
 * 
 * @author xkarlak
 */

public class KeyStoreFileReaderException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = -5798577450165191081L;

    /**
     * Creates an exception with a message.
     * 
     * @param message
     *            The message describing the error.
     */

    public KeyStoreFileReaderException(final String message) {
        super(message);

    }

    /**
     * Creates an exception with a cause.
     * 
     * @param cause
     *            The cause of the exception.
     */

    public KeyStoreFileReaderException(final Throwable cause) {
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

    public KeyStoreFileReaderException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
