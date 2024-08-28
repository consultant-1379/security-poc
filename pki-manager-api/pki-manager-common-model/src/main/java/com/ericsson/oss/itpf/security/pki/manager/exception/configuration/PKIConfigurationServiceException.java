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
package com.ericsson.oss.itpf.security.pki.manager.exception.configuration;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

/**
 * This exception is thrown to indicate any internal database errors or any unconditional exceptions.
 */
public class PKIConfigurationServiceException extends PKIConfigurationException {

    private static final long serialVersionUID = 7859373150121261186L;

    /**
     * Constructs a new PKIConfigurationServiceException
     */
    public PKIConfigurationServiceException() {
        super();
    }

    /**
     * Constructs a new PKIConfigurationServiceException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public PKIConfigurationServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new PKIConfigurationServiceException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public PKIConfigurationServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new PKIConfigurationServiceException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public PKIConfigurationServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
