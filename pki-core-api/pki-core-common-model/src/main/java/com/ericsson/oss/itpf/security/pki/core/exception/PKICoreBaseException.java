/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.exception;

import javax.ejb.ApplicationException;

/**
 * This Exception is parent exception for all the exceptions thrown from all the services in PKI Core.
 *
 * @author tcsrrch
 *
 */
@ApplicationException(rollback = true)
public class PKICoreBaseException extends RuntimeException {

    private static final long serialVersionUID = -8493860339813390282L;

    /**
     * Constructs a new PKICoreBaseException
     */
    public PKICoreBaseException() {
        super();
    }

    /**
     * Constructs a new PKICoreBaseException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public PKICoreBaseException(final String message) {
        super(message);
    }

    /**
     * Constructs a new PKICoreBaseException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public PKICoreBaseException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new PKICoreBaseException with detailed message and cause
     *
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public PKICoreBaseException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
