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

import java.util.Arrays;

/**
 * The CLI command data containing the specified command parameters and properties.
 */
public class CliCommand {
    private static final int MAX_COMMAND_ARGS = 11;
    private final String fullCommand;
    private final String commandContext;
    private final String subCommand;
    private final String operation;
    private final String[] parameters;

    public CliCommand(final String fullCommand) {
        this.fullCommand = fullCommand.trim().replaceAll("\\s+", " ");
        String[] commandArgs = getCommandArgsArray(this.fullCommand);
        commandContext = commandArgs.length != 0 ? commandArgs[0] : "";
        subCommand = commandArgs.length > 1 ? commandArgs[1] : "";
        operation = commandArgs.length > 2 ? commandArgs[2] : "";
        parameters = commandArgs.length > 3 ? Arrays.copyOfRange(commandArgs, 3, commandArgs.length) : new String[0];
    }

    private String[] getCommandArgsArray(final String fullCommand) {
        return fullCommand.split("\\s+", MAX_COMMAND_ARGS);
    }

    /**
     * Get the operation
     *
     * @return operation
     */
    public String getOperation() {
        return operation;
    }

    /**
     * Get the command context
     *
     * @return command context
     */
    public String getCommandContext() {
        return commandContext;
    }

    /**
     * Get the sub command
     *
     * @return sub command
     */
    public String getSubCommand() {
        return subCommand;
    }

    /**
     * Get command parameters
     *
     * @return command parameters
     */
    public String[] getParameters() {
        return parameters;
    }

    /**
     * Get the full command
     *
     * @return full command
     */
    public String getFullCommand() {
        return fullCommand;
    }

    /**
     * Get the string of full command
     *
     * @return the string of full command
     */
    @Override
    public String toString() {
        return fullCommand;
    }
}
