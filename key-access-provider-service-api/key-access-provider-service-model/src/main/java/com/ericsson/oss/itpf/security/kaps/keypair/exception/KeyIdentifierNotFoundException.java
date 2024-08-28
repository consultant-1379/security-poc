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
package com.ericsson.oss.itpf.security.kaps.keypair.exception;

import com.ericsson.oss.itpf.security.kaps.exception.KeyPairException;

/**
 * This exception is thrown in case of KeyIdentifier not found.
 * 
 * @author xramcho
 * 
 */
public class KeyIdentifierNotFoundException extends KeyPairException {

    private static final long serialVersionUID = 7928549213182497070L;

    /**
     * Constructs a new KeyIdentifierNotFoundException with detailed message
     * 
     * @param errorMessage
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public KeyIdentifierNotFoundException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new KeyIdentifierNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KeyIdentifierNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new KeyIdentifierNotFoundException with detailed message and cause
     * 
     * @param errorMessage
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KeyIdentifierNotFoundException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
