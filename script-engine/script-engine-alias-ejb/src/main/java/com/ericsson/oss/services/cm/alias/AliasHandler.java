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
package com.ericsson.oss.services.cm.alias;

import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.ALIAS_ALREADY_EXISTS_ERROR_CODE;
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_CODE;
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.ALIAS_SYNTAX_ERROR_CODE;
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_SYNTAX_ERROR;
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.SUCCESS;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.eventbus.ChannelLocator;
import com.ericsson.oss.services.cli.alias.model.CliAlias;
import com.ericsson.oss.services.cm.alias.events.dps.DatabaseStatus;
import com.ericsson.oss.services.cm.alias.exceptions.AliasCreateInvalidArgumentsException;
import com.ericsson.oss.services.cm.alias.exceptions.AliasInvalidSyntaxException;
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl;
import com.ericsson.oss.services.cm.error.exception.DatabaseNotAvailableException;
import com.ericsson.oss.services.scriptengine.api.ServiceFinderBeanProvider;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

/**
 * Alias commands allow the use of aliases for other commands.
 * example: alias "ls" "cmedit get * networkelement" creates an alias and executing "ls" will resolve to "cmedit get * networkelement".
 */
public class AliasHandler implements CommandHandler {

    public static final String ALIAS_CREATE_SUCCESS_MESSAGE = "alias created";

    @Inject
    private ErrorHandlerImpl errorHandler;

    @Inject
    private AliasParser aliasParser;

    @Inject
    private AliasDao aliasDao;

    @Inject
    private DatabaseStatus databaseStatus;

    @Inject
    private ChannelLocator channelLocator;

    @Inject
    private ServiceFinderBeanProvider serviceFinderBeanProvider;

    /**
     * Check if the specified command is an alias command.
     * Stores the CliAlias in the {@link com.ericsson.oss.services.cli.alias.model.CliAliasCache} if an alias is found.
     * Throws {@link DatabaseNotAvailableException} if the database is not available.
     *
     * @param command
     *         the command received in the request.
     * @return boolean true if the command is an alias.
     */
    public boolean isAlias(final Command command) {
        if (databaseStatus.isAvailable()) {
            return aliasDao.isDefinedAlias(command.getCommandContext());
        } else {
            throw new DatabaseNotAvailableException();
        }
    }

    /**
     * Resolve the alias command by getting the {@link CliAlias} object that represents it.
     *
     * @param command
     *         the command received in the request.
     * @return the resolved command based on the alias and the command arguments.
     * this method is called after the {@link #isAlias(Command)}. To avoid unnecessary calls to DPS the {@link CliAlias} object is cached in
     * the CliAliasCache, see {@link AliasCache}. This method resolves the alias from the cache entry for that name.
     */
    public Command resolveAlias(final Command command) {
        final CliAlias cliAlias = aliasDao.getAlias(command.getCommandContext());
        return new Command(cliAlias.commandContext, aliasParser.getAliasedCommandAfterArgumentSubstitution(command, cliAlias.command));
    }

    /**
     * Creates an alias in persistence, all commands that start with 'alias' are considered alias create commands.
     * CommandSets cannot be aliased, for example: 'alias "cmedit" "cmedit get * NetworkElement"'
     * @throws DatabaseNotAvailableException if the database is not available.
     *
     * @param command
     *         the command received in the request.
     * @return the {@link CommandResponseDto} containing the result of the alias command execution.
     */
    @Override
    public CommandResponseDto execute(final Command command) {
        if (databaseStatus.isAvailable()) {
            final CliAlias cliAlias;
            try {
                cliAlias = aliasParser.parseAliasCreateCommand(command);
                if (aliasNameConflictsWithCommandSetName(cliAlias)) {
                    return unsuccessfulResponseForAlias(command, ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_CODE, cliAlias.name);
                }
            } catch (final AliasInvalidSyntaxException e) {
                return unsuccessfulResponseForAlias(command, ALIAS_SYNTAX_ERROR_CODE);
            } catch (final AliasCreateInvalidArgumentsException e) {
                return unsuccessfulResponseForAlias(command, e.getErrorCode());
            }
            if (aliasDao.isDefinedAlias(cliAlias.name)) {
                return unsuccessfulResponseForAlias(command, ALIAS_ALREADY_EXISTS_ERROR_CODE, cliAlias.name);
            }
            aliasDao.createAlias(cliAlias);
            return successfulResponseForAlias(command);
        } else {
            throw new DatabaseNotAvailableException();
        }
    }

    /*
     * P R I V A T E - M E T H O D S
     */

    private boolean aliasNameConflictsWithCommandSetName(final CliAlias cliAlias) {
        return aliasNameEqualsCommandHandlerChannel(cliAlias.name) || aliasNameEqualsCommandHandlerService(cliAlias.name);
    }

    private boolean aliasNameEqualsCommandHandlerChannel(final String aliasName) {
        return channelLocator.lookupChannel(String.format("jms:/queue/commandHandler.%s", aliasName)) != null;
    }

    private boolean aliasNameEqualsCommandHandlerService(final String aliasName) {
        return !serviceFinderBeanProvider.getServiceFinderBean().findAll(CommandHandler.class, aliasName).isEmpty();
    }

    private CommandResponseDto successfulResponseForAlias(final Command command) {
        final CommandResponseDto response = new CommandResponseDto();
        response.setStatusMessage(ALIAS_CREATE_SUCCESS_MESSAGE);
        response.setCommand(command.toString());
        response.setStatusCode(SUCCESS);
        response.addSuccessLines();
        return response;
    }

    private CommandResponseDto unsuccessfulResponseForAlias(final Command command, final int errorCode, final Object... aliasInfo) {
        final CommandResponseDto response = new CommandResponseDto();
        response.setCommand(command.toString());
        response.setStatusCode(COMMAND_SYNTAX_ERROR);
        response.setErrorCode(errorCode);
        response.setErrorMessage(errorHandler.createErrorMessage(errorCode, aliasInfo));
        response.setSolution(errorHandler.createSolutionMessage(errorCode, aliasInfo));
        response.addErrorLines();
        return response;
    }
}