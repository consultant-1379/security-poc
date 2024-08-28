/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

/**
 * This exception is the parent for all custom configuration related exceptions..
 */
public class CustomConfigurationException extends PKIConfigurationException {

    private static final long serialVersionUID = 7859373150121261186L;

    /**
     * Constructs a new CustomConfigurationException
     */
    public CustomConfigurationException() {
        super();
    }

    /**
     * Constructs a new CustomConfigurationException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CustomConfigurationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CustomConfigurationException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CustomConfigurationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CustomConfigurationException with detailed message and cause
     *
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CustomConfigurationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
