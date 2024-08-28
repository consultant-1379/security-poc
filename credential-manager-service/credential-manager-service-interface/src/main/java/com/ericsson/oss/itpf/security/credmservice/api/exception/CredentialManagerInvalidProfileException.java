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

public class CredentialManagerInvalidProfileException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 1918069340784514551L;

    public CredentialManagerInvalidProfileException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.PROFILE_INVALID, errorMessage), cause);
    }

    public CredentialManagerInvalidProfileException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.PROFILE_INVALID, errorMessage));
    }

    public CredentialManagerInvalidProfileException(final Throwable cause) {
        super(CredentialManagerErrorCodes.PROFILE_INVALID, cause);
    }

    public CredentialManagerInvalidProfileException() {
        super(CredentialManagerErrorCodes.PROFILE_INVALID);
    }

}