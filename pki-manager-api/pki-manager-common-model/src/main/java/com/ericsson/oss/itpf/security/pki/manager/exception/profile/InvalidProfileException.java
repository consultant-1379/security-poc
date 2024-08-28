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
 * This exception is thrown when the given profile is invalid.
 */
public class InvalidProfileException extends ProfileException {

    private static final long serialVersionUID = -7689910342039241620L;

    /**
     * Constructs a new InvalidProfileException
     */
    public InvalidProfileException() {
        super();
    }

    /**
     * Constructs a new InvalidProfileException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public InvalidProfileException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidProfileException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public InvalidProfileException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidProfileException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public InvalidProfileException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
