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
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.RECEIVED_NULL_MESSAGE_ERROR_CODE;
import javax.inject.Inject;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.services.cm.admin.cli.CliCommand;
import com.ericsson.oss.services.cm.admin.cli.CliCommandHandler;
import com.ericsson.oss.services.cm.admin.cli.parser.ExtendedCommandParser;
import com.ericsson.oss.services.cm.admin.cli.response.CommandResponseDtoHelper;
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

/**
 * Abstract implementation of a {@link CliCommandHandler}.
 */
public abstract class AbstractCommandHandler implements CliCommandHandler {
    @Inject
    private ErrorHandlerImpl errorHandler;
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Process the command.
     *
     * @param command
     *            the CLI command
     * @return command response
     */
    @Override
    public CommandResponseDto processCommand(final CliCommand command) {
        try {
            return executeCommand(command);
        } catch (final ParseException e) {
            return CommandResponseDtoHelper.fromErrorCode(SYNTAX_ERROR_CODE, errorHandler.createErrorMessage(SYNTAX_ERROR_CODE),
                    errorHandler.createSolutionMessage(SYNTAX_ERROR_CODE, command.getCommandContext() + " " + command.getSubCommand())).getResponseDto();
        } catch (final Exception e) {
            return CommandResponseDtoHelper
                    .fromErrorCode(RECEIVED_NULL_MESSAGE_ERROR_CODE, errorHandler.createErrorMessage(RECEIVED_NULL_MESSAGE_ERROR_CODE),
                            errorHandler.createSolutionMessage(RECEIVED_NULL_MESSAGE_ERROR_CODE))
                    .getResponseDto();
        }
    }

    private CommandResponseDto executeCommand(final CliCommand command) throws ParseException {
        final CommandLine commandOptions = validateCommand(command);
        return executeCommand(command, commandOptions);
    }

    /**
     * Validate the command syntax.
     *
     * @param cliCommand
     *            the CLI command
     * @return the parsed command line if valid
     * @throws ParseException
     *             if command arguments are not valid
     */
    protected CommandLine validateCommand(final CliCommand cliCommand) throws ParseException {
        final ExtendedCommandParser parser = new ExtendedCommandParser();
        final Options options = getCommandOptions();
        return parser.parse(options, cliCommand.getParameters());
    }

    protected abstract CommandResponseDto executeCommand(final CliCommand command, final CommandLine commandOptions);

    protected abstract Options getCommandOptions();

}