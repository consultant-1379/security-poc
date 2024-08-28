/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 * 
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm;

import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;

/**
 * This exception is thrown when the given algorithm category is invalid.
 */
public class InvalidAlgorithmCategoryException extends AlgorithmException {

    private static final long serialVersionUID = -33239221384831601L;

    /**
     * Constructs a new InvalidAlgorithmCategoryException
     */
    public InvalidAlgorithmCategoryException() {
        super();
    }

    /**
     * Constructs a new InvalidAlgorithmCategoryException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidAlgorithmCategoryException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidAlgorithmCategoryException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidAlgorithmCategoryException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidAlgorithmCategoryException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidAlgorithmCategoryException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
