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
package com.ericsson.oss.itpf.security.pki.core.exception.revocation;

import com.ericsson.oss.itpf.security.pki.core.exception.RevocationException;

/**
 * This exception is thrown to indicate any internal database errors in case of Revocation.
 *
 * @author xvambur
 */
public class RevocationServiceException extends RevocationException {

    private static final long serialVersionUID = 6251727243298288430L;

    /**
     * Constructs a new RevocationServiceException with detailed message
     *
     * @param errorMessage
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public RevocationServiceException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new RevocationServiceException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public RevocationServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new RevocationServiceException with detailed message and cause
     *
     * @param errorMessage
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public RevocationServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
