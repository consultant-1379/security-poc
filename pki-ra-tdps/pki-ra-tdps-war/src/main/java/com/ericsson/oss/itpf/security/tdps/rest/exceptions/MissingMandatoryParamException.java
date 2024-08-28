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
 * This exception is thrown to the Rest service if the provided any of the path parameters are null
 * 
 * @author tcsdemi
 *
 */
public class MissingMandatoryParamException extends RuntimeException {

    private static final long serialVersionUID = -3393768284413373376L;

    /**
     * Constructs a new MissingMandatoryParamException
     */
    public MissingMandatoryParamException() {
        super();
    }

    /**
     * Constructs a new MissingMandatoryParamException with message
     * 
     * @param message
     *            The detailed message
     */
    public MissingMandatoryParamException(final String message) {
        super(message);
    }

    /**
     * Constructs a new MissingMandatoryParamException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public MissingMandatoryParamException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new MissingMandatoryParamException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public MissingMandatoryParamException(final Throwable cause) {
        super(cause);
    }
}
