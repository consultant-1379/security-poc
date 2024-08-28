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

public class CertificateUtilityException extends RuntimeException {

    private static final long serialVersionUID = -4789508716966002843L;

    public CertificateUtilityException() {
        super();
    }

    public CertificateUtilityException(final String message) {
        super(message);
    }

    public CertificateUtilityException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
