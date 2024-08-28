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
package com.ericsson.oss.services.cm.admin.cli;

import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This factory is responsible to provide the {@link CliCommandHandler} for the specified operation.
 */
public class CliCommandHandlerFactory {

    @Inject
    @Any
    private Instance<CliCommandHandler> cliCommandHandlers;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * This method takes a {@link CliCommand} as the input parameter and return the appropriate instance of {@link CliCommandHandler}.
     *
     * @param cliCommand
     *            object representing the command given by the user
     * @return {@link CliCommandHandler} object for the provided command, or the default handler for invalid commands
     */
    public CliCommandHandler getCliCommandHandler(final CliCommand cliCommand) {
        return getHandler(cliCommand.getOperation(), cliCommand.getSubCommand());
    }

    private CliCommandHandler getHandler(final String operation, final String subCommand) {
        String commandHandlerName = isValidOperation(subCommand, operation) ? operation : "default";

        for (final CliCommandHandler cliCommandHandler : cliCommandHandlers) {
            if (cliCommandHandler.getClass().getName().toLowerCase().contains(commandHandlerName)) {
                return cliCommandHandler;
            }
        }
        logger.warn("No handler found for subcommand: {}, operation: {}", subCommand, operation);
        return null;
    }

    private Boolean isValidOperation(final String subCommand, final String operation) {
        return ((subCommand.equals("parameter")) && (operation.equals("view") || operation.equals("modify")));
    }
}