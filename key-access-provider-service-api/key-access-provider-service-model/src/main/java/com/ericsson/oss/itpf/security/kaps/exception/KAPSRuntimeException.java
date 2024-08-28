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
package com.ericsson.oss.itpf.security.kaps.exception;

import javax.ejb.ApplicationException;

/**
 * This Exception is parent exception of all the exceptions thrown from all the services in Key Access provider Service.
 * 
 * @author xramcho
 * 
 */
@ApplicationException(rollback = true)
public class KAPSRuntimeException extends Exception {

    private static final long serialVersionUID = -6922593710590249845L;

    /**
     * Constructs a new KAPSException with detailed message
     * 
     * @param errorMessage
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public KAPSRuntimeException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new KAPSException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KAPSRuntimeException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new KAPSException with detailed message and cause
     * 
     * @param errorMessage
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KAPSRuntimeException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
