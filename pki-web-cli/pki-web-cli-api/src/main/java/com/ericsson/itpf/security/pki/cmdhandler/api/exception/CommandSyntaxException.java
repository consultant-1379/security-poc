/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.itpf.security.pki.cmdhandler.api.exception;

/**
 * Exception class can be used in case any command syntax error occurs
 * 
 * @author xsumnan on 29/03/2015.
 */
public class CommandSyntaxException extends PkiWebCliException {
    private static final long serialVersionUID = 3509806957175133050L;

    {
            setSuggestedSolution(PkiErrorCodes.CHECK_ONLINE_HELP);
    }

    public CommandSyntaxException() {
        super(PkiErrorCodes.SYNTAX_ERROR);
    }

    public CommandSyntaxException(final String message) {
        super(formatMessage(PkiErrorCodes.SYNTAX_ERROR, message));
    }

    public CommandSyntaxException(final String message, final Throwable cause) {
        super(formatMessage(PkiErrorCodes.SYNTAX_ERROR, message), cause);
    }

    public CommandSyntaxException(final Throwable cause) {
        super(PkiErrorCodes.SYNTAX_ERROR, cause);
    }

    /**
     * Gets the error type
     * 
     * @return ErrorType.COMMAND_SYNTAX_ERROR
     */
    @Override
    public ErrorType getErrorType() {
        return ErrorType.COMMAND_SYNTAX_ERROR;
    }
}
