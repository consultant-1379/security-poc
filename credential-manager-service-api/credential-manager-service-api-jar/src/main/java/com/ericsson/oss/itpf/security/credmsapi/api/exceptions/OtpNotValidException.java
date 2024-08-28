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
package com.ericsson.oss.itpf.security.credmsapi.api.exceptions;

public class OtpNotValidException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -2614871025948043059L;

    /**
     * 
     */
    public OtpNotValidException() {
    }

    /**
     * @param message
     */
    public OtpNotValidException(final String message) {
        super("credential-manager-service-api: OtpNotValid: " + message);
    }

    /**
     * @param cause
     */
    public OtpNotValidException(final Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public OtpNotValidException(final String message, final Throwable cause) {
        super("credential-manager-service-api: OtpNotValid: " + message, cause);
    }

}
