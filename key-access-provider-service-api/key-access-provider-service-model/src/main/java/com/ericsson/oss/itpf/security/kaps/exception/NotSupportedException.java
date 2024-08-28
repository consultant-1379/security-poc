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

/**
 * This exception is thrown when unsupported operation was encountered.
 * 
 * @author xramcho
 * 
 */
public class NotSupportedException extends KAPSRuntimeException {

    private static final long serialVersionUID = 1833222789553218120L;

    /**
     * Constructs a new NotSupportedException with detailed message
     * 
     * @param errorMessage
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public NotSupportedException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new NotSupportedException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public NotSupportedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new NotSupportedException with detailed message and cause
     * 
     * @param errorMessage
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public NotSupportedException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
