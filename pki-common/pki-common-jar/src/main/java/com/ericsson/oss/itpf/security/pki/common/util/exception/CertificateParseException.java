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
package com.ericsson.oss.itpf.security.pki.common.util.exception;

public class CertificateParseException extends RuntimeException {

    private static final long serialVersionUID = -6646065775913639825L;

    public CertificateParseException() {
        super();
    }

    public CertificateParseException(final String message) {
        super(message);
    }

    public CertificateParseException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
