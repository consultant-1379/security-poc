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

public class AlreadyRevokedCertificateException extends Exception {

    private static final long serialVersionUID = 1215728607922223799L;

    public AlreadyRevokedCertificateException() {

    }

    /**
     * @param message
     */
    public AlreadyRevokedCertificateException(final String message) {
        super("credential-manager-service-api: AlreadyRevokedCertificate: " + message);

    }

    /**
     * @param cause
     */
    public AlreadyRevokedCertificateException(final Throwable cause) {
        super(cause);

    }

    /**
     * @param message
     * @param cause
     */
    public AlreadyRevokedCertificateException(final String message, final Throwable cause) {
        super("credential-manager-service-api: AlreadyRevokedCertificate: " + message, cause);

    }

}
