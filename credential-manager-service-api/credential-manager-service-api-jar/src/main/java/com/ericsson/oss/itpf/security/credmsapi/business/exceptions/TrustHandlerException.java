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
package com.ericsson.oss.itpf.security.credmsapi.business.exceptions;

public class TrustHandlerException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = 2742349678405070111L;

    /**
	 * 
	 */
    public TrustHandlerException() {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * @param message
     * @param cause
     */
    public TrustHandlerException(final String message, final Throwable cause) {
        super("credential-manager-service-api: trustHandler: " + message, cause);
        // TODO Auto-generated constructor stub
    }

    /**
     * @param message
     */
    public TrustHandlerException(final String message) {
        super("credential-manager-service-api: trustHandler: " + message);
        // TODO Auto-generated constructor stub
    }

    /**
     * @param cause
     */
    public TrustHandlerException(final Throwable cause) {
        super(cause);
        // TODO Auto-generated constructor stub
    }

}
