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
 * Exception class can be used in case CommandHandler Not recognized
 * 
 * @author xsumnan on 29/03/2015.
 */
public class CouldNotFindCommandHandlerException extends PkiWebCliException {

    private static final long serialVersionUID = 1L;

    public CouldNotFindCommandHandlerException(final Exception e) {
        super(e.getMessage());
    }

    public CouldNotFindCommandHandlerException(final String message) {
        super(formatMessage(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, message));
    }

    @Override
    public ErrorType getErrorType() {
        return ErrorType.COMMAND_HANDLER_NOT_FOUND_ERROR;
    }

}
