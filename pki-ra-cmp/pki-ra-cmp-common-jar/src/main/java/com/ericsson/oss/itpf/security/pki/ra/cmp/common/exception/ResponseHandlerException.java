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
 * This exception is thrown whenever there is any errored response sent from
 * PKI-manager over the modeled event bus.
 * 
 * @author tcsdemi
 *
 */
public class ResponseHandlerException extends ProtocolException {

    private static final long serialVersionUID = 2045363536824168473L;

    public ResponseHandlerException() {
        super();
    }

    /**
     * This exception is thrown whenever there is any errored response sent from
     * PKI-manager over the modeled event bus.
     * 
     * @param errorMessage
     *            This is a user defined errorMessage
     */
    public ResponseHandlerException(final String errorMessage) {
        super(errorMessage);
    }




}
