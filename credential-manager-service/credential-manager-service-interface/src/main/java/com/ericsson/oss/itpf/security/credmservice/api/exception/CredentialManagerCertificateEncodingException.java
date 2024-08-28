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

public class CredentialManagerCertificateEncodingException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 5923774954657927972L;

    public CredentialManagerCertificateEncodingException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR, errorMessage), cause);
    }

    public CredentialManagerCertificateEncodingException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR, errorMessage));
    }

    public CredentialManagerCertificateEncodingException(final Throwable cause) {
        super(CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR, cause);
    }

    public CredentialManagerCertificateEncodingException() {
        super(CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR);
    }

}