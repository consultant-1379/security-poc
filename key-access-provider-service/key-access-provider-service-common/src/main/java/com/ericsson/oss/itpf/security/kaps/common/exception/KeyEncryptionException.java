/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.kaps.common.exception;

/**
 * This exception is thrown when key pair encryption is failed.
 */
public class KeyEncryptionException extends RuntimeException {

    private static final long serialVersionUID = -7069606615327718609L;

    /**
     * Constructs a new KeyEncryptionException with detailed message
     * 
     * @param errorMessage
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public KeyEncryptionException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new KeyEncryptionException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KeyEncryptionException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new KeyEncryptionException with detailed message and cause
     * 
     * @param errorMessage
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KeyEncryptionException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
