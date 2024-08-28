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
 * This Exception is thrown when given Profile doesn't exists or in inactive state.
 * 
 */
public class ProfileNotFoundException extends ProfileException {

    private static final long serialVersionUID = -8671532264700636505L;

    /**
     * Constructs a new ProfileNotFoundException
     */
    public ProfileNotFoundException() {
        super();
    }

    /**
     * Constructs a new ProfileNotFoundException with detailed message
     * 
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public ProfileNotFoundException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new ProfileNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public ProfileNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ProfileNotFoundException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public ProfileNotFoundException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
