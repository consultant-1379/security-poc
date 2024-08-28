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
package com.ericsson.oss.itpf.security.pki.manager.exception.revocation;

import com.ericsson.oss.itpf.security.pki.manager.exception.RevocationException;

/**
 * This exception is thrown when the user provided InvalidityDate is beyond the certificate Validity during certificate revocation.
 *
 * @author xsrirko
 */

public class InvalidInvalidityDateException extends RevocationException {

    private static final long serialVersionUID = 6251727243298288430L;

    /**
     * Constructs a new InvalidInvalidityDateException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public InvalidInvalidityDateException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new InvalidInvalidityDateException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidInvalidityDateException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidInvalidityDateException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidInvalidityDateException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
