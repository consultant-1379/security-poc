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

public class CredentialManagerInvalidEntityException extends CredentialManagerServiceException {

    private static final long serialVersionUID = -4252001977157687012L;

    public CredentialManagerInvalidEntityException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.ENTITY_INVALID, errorMessage), cause);
    }

    public CredentialManagerInvalidEntityException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.ENTITY_INVALID, errorMessage));
    }

    public CredentialManagerInvalidEntityException(final Throwable cause) {
        super(CredentialManagerErrorCodes.ENTITY_INVALID, cause);
    }

    public CredentialManagerInvalidEntityException() {
        super(CredentialManagerErrorCodes.ENTITY_INVALID);
    }

}