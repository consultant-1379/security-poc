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
package com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement;

import com.ericsson.oss.itpf.security.pki.core.exception.CRLException;


/**
 * CRLServiceException is thrown, if any database failures occurs in case of CRL operations.
 *
 * @author xramdag
 *
 */
public class CRLServiceException extends CRLException {

    private static final long serialVersionUID = 1962666176691104526L;

    /**
     * Constructs a new CRLServiceException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CRLServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CRLServiceException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CRLServiceException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
