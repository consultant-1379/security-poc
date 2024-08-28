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

/**
 * This exception is .
 */
public class CustomConfigurationInvalidException extends CustomConfigurationException {

    private static final long serialVersionUID = -1430756125608339530L;

    /**
     * Constructs a new CustomConfigurationInvalidException
     */
    public CustomConfigurationInvalidException() {
        super();
    }

    /**
     * Constructs a new CustomConfigurationInvalidException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public CustomConfigurationInvalidException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CustomConfigurationInvalidException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CustomConfigurationInvalidException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CustomConfigurationInvalidException with detailed message and cause
     *
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CustomConfigurationInvalidException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
