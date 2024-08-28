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

public class CertificateNotFoundException extends Exception {

    private static final long serialVersionUID = 2419307674410573494L;

    /**
     * 
     */
    public CertificateNotFoundException() {
        super();

    }

    /**
     * @param message
     * @param cause
     */
    public CertificateNotFoundException(final String message, final Throwable cause) {
        super("credential-manager-service-api: CertificateNotFound: " + message, cause);

    }

    /**
     * @param message
     */
    public CertificateNotFoundException(final String message) {
        super("credential-manager-service-api: CertificateNotFound: " + message);

    }

    /**
     * @param cause
     */
    public CertificateNotFoundException(final Throwable cause) {
        super(cause);

    }

}
