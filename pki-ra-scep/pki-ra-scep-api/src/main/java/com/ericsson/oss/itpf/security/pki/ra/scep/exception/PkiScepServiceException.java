/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.exception;

/**
 * PkiScepServiceException will be thrown when an exception occurs while processing the request or building the response.
 * 
 * @author xananer
 */
public class PkiScepServiceException extends ProtocolException {

    private static final long serialVersionUID = 1L;

    /**
     * @param msg
     */
    public PkiScepServiceException(final String msg) {
        super(msg);
    }

    public PkiScepServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
