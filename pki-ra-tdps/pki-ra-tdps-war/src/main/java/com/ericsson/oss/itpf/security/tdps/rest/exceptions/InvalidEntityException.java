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
package com.ericsson.oss.itpf.security.tdps.rest.exceptions;

/**
 * This exception is thrown when TDPSentity type in URL is not valid i.e it is not CA_ENTITY or ENTITY.
 * 
 * @author tcsdemi
 *
 */
public class InvalidEntityException extends RuntimeException {

    private static final long serialVersionUID = -2854064421713657804L;

    /**
     * Constructs a new InvalidEntityException
     */
    public InvalidEntityException() {
        super();
    }

    /**
     * Constructs a new InvalidEntityException with message
     * 
     * @param message
     *            The detailed message
     */
    public InvalidEntityException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidEntityException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public InvalidEntityException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new InvalidEntityException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public InvalidEntityException(final Throwable cause) {
        super(cause);
    }
}
