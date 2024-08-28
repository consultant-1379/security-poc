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
 * This Exception is thrown when creating a profile that already exists.
 * 
 */
public class ProfileAlreadyExistsException extends ProfileException {

    private static final long serialVersionUID = 3060152457914977646L;

    /**
     * Constructs a new ProfileAlreadyExistsException
     */
    public ProfileAlreadyExistsException() {
        super();
    }

    /**
     * Constructs a new ProfileAlreadyExistsException with detailed message
     * 
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public ProfileAlreadyExistsException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new ProfileAlreadyExistsException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public ProfileAlreadyExistsException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ProfileAlreadyExistsException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public ProfileAlreadyExistsException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
