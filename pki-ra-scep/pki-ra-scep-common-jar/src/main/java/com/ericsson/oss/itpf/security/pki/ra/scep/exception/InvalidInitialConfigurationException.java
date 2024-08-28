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
package com.ericsson.oss.itpf.security.pki.ra.scep.exception;

import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This exception is thrown whenever any initial configuration data is invalid or is not consistent
 * 
 * @author xchowja
 *
 */
public class InvalidInitialConfigurationException extends ProtocolException {

    private static final long serialVersionUID = 245668185037173826L;

    public InvalidInitialConfigurationException() {
        super();
    }

    /**
     * This exception is thrown whenever any initial configuration data is invalid or is not consistent
     * 
     * @param errorMessage
     *            It is a user defined errorMessage
     */
    public InvalidInitialConfigurationException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * This exception is thrown whenever a custom exception regarding innvalid initial configuration needs to be wrapped over any java security exceptions or any 3pp exceptions
     * 
     * @param errorMessage
     *            It is a user defined errorMessage
     * @param cause
     *            It is the throwable object which is needs to be carried forward for maintaining original stacktrace.
     * 
     */
    public InvalidInitialConfigurationException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
