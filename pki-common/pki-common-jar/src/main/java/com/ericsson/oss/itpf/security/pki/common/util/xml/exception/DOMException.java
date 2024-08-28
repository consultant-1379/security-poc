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
package com.ericsson.oss.itpf.security.pki.common.util.xml.exception;

/**
 * This exception is thrown when error occurs in DOM related operations.
 * 
 * @author xnagsow
 *
 */
public class DOMException extends XMLException {
    private static final long serialVersionUID = -1184272883049131758L;

    /**
     * Constructs a new DOMException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public DOMException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new DOMException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public DOMException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new DOMException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public DOMException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
