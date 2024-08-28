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
 * This exception is thrown when failed to parse Document DOM XML object.
 * 
 * @author xnagsow
 *
 */
public class XMLParseException extends XMLException {
    private static final long serialVersionUID = -1184272883049131758L;

    /**
     * Constructs a new XMLParseException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public XMLParseException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new XMLParseException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public XMLParseException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new XMLParseException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public XMLParseException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
