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
 * CRLDistributionPointServiceException occurs when the Exception is thrown when any internal service like database service throw an exception
 *
 * @author xjagcho
 */
@ApplicationException(rollback = true) 
public class CRLDistributionPointServiceException extends RuntimeException {

    private static final long serialVersionUID = -1824407529210948951L;

    /**
     * * @param message the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     */
    public CRLDistributionPointServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CRLDistributionPointServiceException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLDistributionPointServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CRLDistributionPointServiceException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed errorMessage (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLDistributionPointServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
