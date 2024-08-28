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
package com.ericsson.oss.itpf.security.pki.common.validator.exception;

/**
 * This exception is thrown when CRL version is not supported.
 * 
 * @author tcsramc
 * 
 */
public class UnsupportedCRLVersionException extends CRLValidationException {
    private static final long serialVersionUID = -3478795753431235433L;

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     */
    public UnsupportedCRLVersionException(final String errorMessage) {
        super(errorMessage);
    }

}
