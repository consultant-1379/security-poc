/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.cli.handler;

import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.SYNTAX_ERROR_CODE;

import javax.inject.Inject;

import com.ericsson.oss.services.cm.admin.cli.CliCommand;
import com.ericsson.oss.services.cm.admin.cli.CliCommandHandler;
import com.ericsson.oss.services.cm.admin.cli.response.CommandResponseDtoHelper;
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;

/**
 * This class extends the {@link CliCommandHandler} and implements the Default command handler.
 */
public class DefaultCommandHandler implements CliCommandHandler {

    @Inject
    private ErrorHandlerImpl errorHandler;

    @Override
    public CommandResponseDto processCommand(final CliCommand cliCommand){
        String adminCmdHelper = cliCommand.getCommandContext();
        final String subCommand = cliCommand.getSubCommand();
        if ("parameter".equals(subCommand)) {
            adminCmdHelper += " " + subCommand;
        }
          return CommandResponseDtoHelper.fromErrorCode(SYNTAX_ERROR_CODE, errorHandler.createErrorMessage(SYNTAX_ERROR_CODE),
                errorHandler.createSolutionMessage(SYNTAX_ERROR_CODE, adminCmdHelper)).getResponseDto();
   }
}