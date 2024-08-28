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
package com.ericsson.oss.itpf.security.credmservice.api.exception;

public class CredentialManagerAlreadyRevokedCertificateException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 4062738474881576315L;

    public CredentialManagerAlreadyRevokedCertificateException(final String errorMessage, final Throwable cause) {
        super(formatMessage(CredentialManagerErrorCodes.REVOKED_CERTIFICATE, errorMessage), cause);
    }

    public CredentialManagerAlreadyRevokedCertificateException(final String errorMessage) {
        super(formatMessage(CredentialManagerErrorCodes.REVOKED_CERTIFICATE, errorMessage));
    }

    public CredentialManagerAlreadyRevokedCertificateException(final Throwable cause) {
        super(CredentialManagerErrorCodes.REVOKED_CERTIFICATE, cause);
    }

    public CredentialManagerAlreadyRevokedCertificateException() {
        super(CredentialManagerErrorCodes.REVOKED_CERTIFICATE);
    }

}
