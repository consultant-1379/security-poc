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

public class GetCertificatesByEntityNameException extends Exception {

    private static final long serialVersionUID = 7851329071505715865L;

    /**
     * 
     */
    public GetCertificatesByEntityNameException() {
        super();

    }

    /**
     * @param message
     * @param cause
     */
    public GetCertificatesByEntityNameException(final String message, final Throwable cause) {
        super("credential-manager-service-api: GetCertificatesByEntityName: " + message, cause);

    }

    /**
     * @param message
     */
    public GetCertificatesByEntityNameException(final String message) {
        super("credential-manager-service-api: GetCertificatesByEntityName: " + message);

    }

    /**
     * @param cause
     */
    public GetCertificatesByEntityNameException(final Throwable cause) {
        super(cause);

    }

}
