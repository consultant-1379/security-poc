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

public class InvalidCertificateFormatException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -4578041478361477735L;
    
    public InvalidCertificateFormatException() {

    }

    /**
     * @param message
     */
    public InvalidCertificateFormatException(final String message) {
        super("credential-manager-service-api: invalid certificate format: " + message);

    }

    /**
     * @param cause
     */
    public InvalidCertificateFormatException(final Throwable cause) {
        super(cause);

    }

    /**
     * @param message
     * @param cause
     */
    public InvalidCertificateFormatException(final String message, final Throwable cause) {
        super("credential-manager-service-api: invalid certificate format: " + message, cause);

    }


}
