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
package com.ericsson.oss.itpf.security.pki.cdps.api.exception;

import javax.ejb.ApplicationException;

/**
 * CRLNotFoundException will be thrown when an exception occurs while processing the request or building the response.
 *
 * @author xjagcho
 */
@ApplicationException(rollback = true) 
public class CRLNotFoundException extends RuntimeException {
    private static final long serialVersionUID = -953521207217119537L;

    /**
     * * @param message the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     */
    public CRLNotFoundException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CRLNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CRLNotFoundException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed errorMessage (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLNotFoundException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
