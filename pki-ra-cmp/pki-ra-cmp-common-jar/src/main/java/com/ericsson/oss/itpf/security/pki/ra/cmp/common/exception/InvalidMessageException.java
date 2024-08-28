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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception;

import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This exception is thrown when message stored in DB is not in proper format or
 * is not of expected type
 * 
 * @author tcsdemi
 *
 */
public class InvalidMessageException extends ProtocolException {

    private static final long serialVersionUID = 4980141384591604150L;

    public InvalidMessageException() {
        super();
    }

    /**
     * * This exception is thrown when message stored in DB is not in proper
     * format or is not of expected type
     * 
     * @param message
     *            This is a user defined errorMessage
     */
    public InvalidMessageException(final String message) {
        super(message);
    }



}
