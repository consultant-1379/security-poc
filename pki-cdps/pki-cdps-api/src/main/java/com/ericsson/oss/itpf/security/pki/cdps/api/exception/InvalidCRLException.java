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
 * InvalidCRLException will be thrown when an the system encounters an invalid CRL.
 *
 * @author xbensar
 */
@ApplicationException(rollback = true)
public class InvalidCRLException extends RuntimeException {
    private static final long serialVersionUID = -953521207217119537L;

    /**
     * * @param message the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     */
    public InvalidCRLException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidCRLException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidCRLException with detailed message and cause
     * 
     * @param errorMessage
     *            the detailed errorMessage (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public InvalidCRLException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
