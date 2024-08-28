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
package com.ericsson.oss.services.cm.error;

import com.ericsson.oss.services.scriptengine.spi.dtos.CommandDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

import javax.inject.Inject;

import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.*;
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.UNEXPECTED_ERROR;

public class ErrorManager {

    @Inject
    private ErrorHandlerImpl errorHandler;

    @Inject
    private ExceptionHelper exceptionHelper;

    public boolean isJmsQueueException(final String queueName, final Exception exception) {
        final String errorMessage = exceptionHelper.getRootCauseAndRewrap(exception).getMessage();
        return (errorMessage != null) && errorMessage.contains(queueName);
    }

    public CommandResponseDto handleUnexpectedException(final Throwable t, final String command) {
        final String errorMessage = exceptionHelper.getRootCauseAndRewrap(t).getMessage();
        return createCommandResponseDtoForErrorCode(ERROR_CODE_UNEXPECTED_ERROR, command, errorMessage);
    }

    public CommandResponseDto handleUnexpectedException(final Throwable t) {
        final String errorMessage = exceptionHelper.getRootCauseAndRewrap(t).getMessage();
        return createCommandResponseDtoForErrorCode(ERROR_CODE_UNEXPECTED_ERROR, null, errorMessage);
    }

    public CommandResponseDto handleDatabaseNotAvailableException(final String command) {
        return createCommandResponseDtoForErrorCode(DATABASE_NOT_AVAILABLE_ERROR_CODE, command, null);
    }

    public CommandResponseDto handleUnrecognisedCommand(final String command) {
        return createCommandResponseDtoForErrorCode(UNRECOGNISED_CLI_COMMAND_CODE, command, null);
    }

    public CommandResponseDto handleReceivingNullMessageFromQueue() {
        return createCommandResponseDtoForErrorCode(RECEIVED_NULL_MESSAGE_ERROR_CODE, null, null);
    }

    public CommandResponseDto handleAccessUnauthorizedException() {
        return createCommandResponseDtoForErrorCode(ACCESS_UNAUTHORIZED_ERROR_CODE, null, null);
    }

    private CommandResponseDto createCommandResponseDtoForErrorCode(final int errorCode, final String command, final String errorMessageFromException) {
        final CommandResponseDto response = new CommandResponseDto();
        if (command != null) {
            response.getResponseDto().getElements().add(new CommandDto(command));
        }
        response.setStatusCode(UNEXPECTED_ERROR);
        response.setErrorCode(errorCode);

        if (errorCode == ERROR_CODE_UNEXPECTED_ERROR) {
            response.setStatusMessage(EXCEPTION_MESSAGE + errorMessageFromException);
        } else {
            final String errorMessage = errorHandler.createErrorMessage(errorCode, command);
            response.setStatusMessage(errorMessage);
            final String solution = errorHandler.createSolutionMessage(errorCode);
            response.setSolution(solution);
        }
        response.addErrorLines();
        return response;
    }
}


