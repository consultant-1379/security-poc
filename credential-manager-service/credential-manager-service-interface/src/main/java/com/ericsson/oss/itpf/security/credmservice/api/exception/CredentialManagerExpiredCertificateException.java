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

public class CredentialManagerExpiredCertificateException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 8156648057526728004L;

    public CredentialManagerExpiredCertificateException(final String errorMessage, final Throwable cause) {
        super(formatMessage(CredentialManagerErrorCodes.EXPIRED_CERTIFICATE, errorMessage), cause);
    }

    public CredentialManagerExpiredCertificateException(final String errorMessage) {
        super(formatMessage(CredentialManagerErrorCodes.EXPIRED_CERTIFICATE, errorMessage));
    }

    public CredentialManagerExpiredCertificateException(final Throwable cause) {
        super(CredentialManagerErrorCodes.EXPIRED_CERTIFICATE, cause);
    }

    public CredentialManagerExpiredCertificateException() {
        super(CredentialManagerErrorCodes.EXPIRED_CERTIFICATE);
    }

}
