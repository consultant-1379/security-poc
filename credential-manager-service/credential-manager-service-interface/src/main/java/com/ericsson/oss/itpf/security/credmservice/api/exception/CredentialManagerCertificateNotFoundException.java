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

public class CredentialManagerCertificateNotFoundException extends CredentialManagerServiceException{

    private static final long serialVersionUID = -242193031361949607L;

    public CredentialManagerCertificateNotFoundException(final String errorMessage, final Throwable cause) {
        super(formatMessage(CredentialManagerErrorCodes.CERTIFICATE_NOT_FOUND, errorMessage), cause);
    }

    public CredentialManagerCertificateNotFoundException(final String errorMessage) {
        super(formatMessage(CredentialManagerErrorCodes.CERTIFICATE_NOT_FOUND, errorMessage));
    }

    public CredentialManagerCertificateNotFoundException(final Throwable cause) {
        super(CredentialManagerErrorCodes.CERTIFICATE_NOT_FOUND, cause);
    }

    public CredentialManagerCertificateNotFoundException() {
        super(CredentialManagerErrorCodes.CERTIFICATE_NOT_FOUND);
    }
    
}
