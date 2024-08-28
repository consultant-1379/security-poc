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
 * This exception is thrown when generation of symmetric key is failed.
 */
public class SymmetricKeyGenerationException extends RuntimeException {

    private static final long serialVersionUID = 3596390586480254112L;

    /**
     * Constructs a new SymmetricKeyGenerationException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public SymmetricKeyGenerationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new SymmetricKeyGenerationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public SymmetricKeyGenerationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new SymmetricKeyGenerationException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public SymmetricKeyGenerationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
