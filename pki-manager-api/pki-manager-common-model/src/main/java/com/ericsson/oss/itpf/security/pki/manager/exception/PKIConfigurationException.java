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
package com.ericsson.oss.itpf.security.pki.manager.exception;

/**
 * This exception is the parent exception of all the Configuration related Exceptions.
 */
public class PKIConfigurationException extends PKIBaseException {

    private static final long serialVersionUID = 4606932664821164906L;

    /**
     * Constructs a new PKIConfigurationException
     */
    public PKIConfigurationException() {
        super();
    }

    /**
     * Constructs a new PKIConfigurationException with detailed message
     * 
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public PKIConfigurationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new PKIConfigurationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public PKIConfigurationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new PKIConfigurationException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public PKIConfigurationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
