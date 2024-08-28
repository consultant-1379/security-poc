/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.exception;

import javax.ejb.ApplicationException;

/**
 * Base exception for all CredentialManager services.
 */
@ApplicationException(rollback = true)
public abstract class CredentialManagerServiceException extends RuntimeException {

    private static final long serialVersionUID = 772136925762150922L;

    private String suggestedSolution = CredentialManagerErrorCodes.SUGGESTED_SOLUTION_CONSULT_ERROR_LOGS;

    protected String errorMessage;

    public CredentialManagerServiceException() {
        super();
    }

    public CredentialManagerServiceException(final String errorMessage) {
        super(errorMessage);
        this.errorMessage = errorMessage;
    }

    public CredentialManagerServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
        this.errorMessage = errorMessage;
    }

    //    public CredentialManagerServiceException(final Throwable cause) {
    //        super(cause);
    //    }

    public String getSuggestedSolution() {
        return suggestedSolution;
    }

    public CredentialManagerServiceException setSuggestedSolution(final String suggestedSolution) {
        this.suggestedSolution = suggestedSolution == null ? "" : suggestedSolution;
        return this;
    }

    public CredentialManagerServiceException setSuggestedSolution(final String suggestedSolution, final Object... args) {
        return setSuggestedSolution(String.format(suggestedSolution, args));
    }

    public final String getErrorMessage() {
        return errorMessage;
    }

    protected static String formatMessage(final String part1, final String part2) {
        return part1 + " : " + part2;
    }
}
