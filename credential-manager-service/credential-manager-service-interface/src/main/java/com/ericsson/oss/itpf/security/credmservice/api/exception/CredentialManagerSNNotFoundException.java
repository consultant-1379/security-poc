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

public class CredentialManagerSNNotFoundException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 6388819223844546669L;

    public CredentialManagerSNNotFoundException(final String errorMessage, final Throwable cause) {
//        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.SN_NOT_FOUND, errorMessage), cause);
    }

    public CredentialManagerSNNotFoundException(final String errorMessage) {
//      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.SN_NOT_FOUND, errorMessage));
    }

    public CredentialManagerSNNotFoundException(final Throwable cause) {
        super(CredentialManagerErrorCodes.SN_NOT_FOUND, cause);
    }

    public CredentialManagerSNNotFoundException() {
        super(CredentialManagerErrorCodes.SN_NOT_FOUND);
    }

}