/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm;


import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

/**
 * This exception is thrown to indicate that the given Algorithm Type is invalid.
 *
 * @author xbensar
 */

public class InvalidAlgorithmTypeException extends PKIConfigurationException {

    private static final long serialVersionUID = -3308049022301715892L;

    /**
     * Constructs a new InvalidAlgorithmTypeException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidAlgorithmTypeException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new InvalidAlgorithmTypeException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidAlgorithmTypeException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidAlgorithmTypeException with detailed message and cause
     *
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidAlgorithmTypeException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
