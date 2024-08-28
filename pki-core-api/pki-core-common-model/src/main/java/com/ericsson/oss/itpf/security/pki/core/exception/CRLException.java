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
package com.ericsson.oss.itpf.security.pki.core.exception;

/**
 *
 * This Exception is parent exception of all the CRL related exceptions.
 *
 */
public class CRLException extends PKICoreBaseException {

    private static final long serialVersionUID = -4870343509393968484L;

    /**
     * Constructs a new CRLException
     */
    public CRLException() {
        super();
    }

    /**
     * Constructs a new CRLException with detailed message
     *
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public CRLException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CRLException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CRLException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CRLException with detailed message and cause
     *
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public CRLException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
