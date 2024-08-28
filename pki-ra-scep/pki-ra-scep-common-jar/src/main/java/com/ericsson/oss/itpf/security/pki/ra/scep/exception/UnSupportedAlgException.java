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
package com.ericsson.oss.itpf.security.pki.ra.scep.exception;

/**
 * UnSupportedAlgException will be thrown when the algorithm is not supported.
 * 
 * @author xshaeru
 */
public class UnSupportedAlgException extends BadRequestException {

    /**
	     *
	     */
    private static final long serialVersionUID = 1L;

    /**
     * This exception is thrown if the the algorithm is not supported.
     * 
     * @param msg
     *            description of the message.
     */
    public UnSupportedAlgException(final String msg) {
        super(msg);
    }
}
