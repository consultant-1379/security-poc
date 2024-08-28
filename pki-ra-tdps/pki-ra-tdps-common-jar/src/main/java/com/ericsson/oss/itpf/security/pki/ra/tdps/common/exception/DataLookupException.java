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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception;

/**
 * 
 * This exception is thrown when if more than one result is found in the Database with a given combination of Entity Name and EntityType and also throws any persistence related exceptions occurs.
 * 
 * @author xchowja
 *
 */
public class DataLookupException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new DataLookupException
     */
    public DataLookupException() {
        super();
    }

    /**
     * Constructs a new DataLookupException with message
     * 
     * @param message
     *            The detailed message
     */
    public DataLookupException(final String message) {
        super(message);

    }

    /**
     * Constructs a new DataLookupException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public DataLookupException(final String message, final Throwable cause) {
        super(message, cause);

    }

    /**
     * Constructs a new DataLookupException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public DataLookupException(final Throwable cause) {
        super(cause);

    }

}
