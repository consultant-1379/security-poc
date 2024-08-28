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

public class CredentialManagerInternalServiceException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 8482095734456832415L;

    public CredentialManagerInternalServiceException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.UNEXPECTED_INTERNAL_ERROR, errorMessage), cause);
    }

    public CredentialManagerInternalServiceException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.UNEXPECTED_INTERNAL_ERROR, errorMessage));
    }

    public CredentialManagerInternalServiceException(final Throwable cause) {
        super(CredentialManagerErrorCodes.UNEXPECTED_INTERNAL_ERROR, cause);
    }

    public CredentialManagerInternalServiceException() {
        super(CredentialManagerErrorCodes.UNEXPECTED_INTERNAL_ERROR);
    }

}