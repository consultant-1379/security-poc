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

public class CredentialManagerInvalidCSRException extends CredentialManagerServiceException {

    private static final long serialVersionUID = -1093757783111483556L;

    public CredentialManagerInvalidCSRException(final String errorMessage, final Throwable cause) {
        //        this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.INVALID_CSR, errorMessage), cause);
    }

    public CredentialManagerInvalidCSRException(final String errorMessage) {
        //      this.setSuggestedSolution()
        super(formatMessage(CredentialManagerErrorCodes.INVALID_CSR, errorMessage));
    }

    public CredentialManagerInvalidCSRException(final Throwable cause) {
        super(CredentialManagerErrorCodes.INVALID_CSR, cause);
    }

    public CredentialManagerInvalidCSRException() {
        super(CredentialManagerErrorCodes.INVALID_CSR);
    }

}