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

public class CredentialManagerEntityNotFoundException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 6388819223844546669L;

    public CredentialManagerEntityNotFoundException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.ENTITY_NOT_FOUND, errorMessage), cause);
    }

    public CredentialManagerEntityNotFoundException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.ENTITY_NOT_FOUND, errorMessage));
    }

    public CredentialManagerEntityNotFoundException(final Throwable cause) {
        super(CredentialManagerErrorCodes.ENTITY_NOT_FOUND, cause);
    }

    public CredentialManagerEntityNotFoundException() {
        super(CredentialManagerErrorCodes.ENTITY_NOT_FOUND);
    }

}