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
package com.ericsson.oss.itpf.security.pki.manager.exception.profile;

import com.ericsson.oss.itpf.security.pki.manager.exception.ProfileException;

/**
 * This exception is thrown when the exceptions related to profile service occurs.
 */
public class ProfileServiceException extends ProfileException {

    private static final long serialVersionUID = -6642523010310839450L;

    /**
     * Constructs a new ProfileServiceException
     */
    public ProfileServiceException() {
        super();
    }

    /**
     * Constructs a new ProfileServiceException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ProfileServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new ProfileServiceException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ProfileServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ProfileServiceException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ProfileServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}