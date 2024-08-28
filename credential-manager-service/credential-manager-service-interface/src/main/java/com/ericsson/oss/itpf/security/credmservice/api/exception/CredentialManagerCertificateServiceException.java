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

public class CredentialManagerCertificateServiceException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 8482095734456832415L;

    public CredentialManagerCertificateServiceException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.CERTIFICATE_SERVICE_ERROR, errorMessage), cause);
    }

    public CredentialManagerCertificateServiceException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.CERTIFICATE_SERVICE_ERROR, errorMessage));
    }

    public CredentialManagerCertificateServiceException(final Throwable cause) {
        super(CredentialManagerErrorCodes.CERTIFICATE_SERVICE_ERROR, cause);
    }

    public CredentialManagerCertificateServiceException() {
        super(CredentialManagerErrorCodes.CERTIFICATE_SERVICE_ERROR);
    }

}