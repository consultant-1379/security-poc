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

package com.ericsson.itpf.security.pki.cmdhandler.api.exception;

/**
 * Exception class to handle any RuntimeException related to command
 * 
 * @author xsumnan on 29/03/2015.
 */
public class PkiCLIException extends RuntimeException {

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    public PkiCLIException(final String s) {
        super(s);
    }

    public PkiCLIException() {
        super("com.ericsson.itpf.security.pki.cmdhandler.command error");
    }
}
