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

package com.ericsson.oss.services.cm.scriptengine.ejb.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import com.ericsson.enm.cm.router.jms.ScriptEngineRequestQueue;
import com.ericsson.enm.cm.router.api.CommandRequest;
//import com.ericsson.enm.cm.router.api.CommandRouter;
import com.ericsson.oss.itpf.sdk.context.ContextService;
//import com.ericsson.oss.itpf.sdk.eventbus.Channel;
//import com.ericsson.oss.services.cm.alias.AliasHandler;
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl;
import com.ericsson.oss.services.cm.error.ErrorManager;
import com.ericsson.oss.services.cm.error.exception.DatabaseNotAvailableException;
import com.ericsson.oss.services.cm.error.exception.UnrecognisedCommandException;
import com.ericsson.oss.services.scriptengine.api.ServiceFinderBeanProvider;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.summary.SummaryDto;
import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;

@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class ScriptEngineCommandExecutor  {

    private static final String COMMAND_REQUEST_CONTEXT_ID = "CM-CLI-Request-ID";
    private static final String ALIAS = "alias";
    private static final Logger logger = LoggerFactory.getLogger(ScriptEngineCommandExecutor.class);
//
//    @Inject
//    private AliasHandler aliasHandler;
//
//    @Inject
//    private CommandRouter commandRouter;

    @Inject
    private ErrorHandlerImpl errorHandler;

    @Inject
    private ErrorManager errorManager;

    @Inject
    private ContextService contextService;

//    @Inject
//    private ScriptEngineRequestQueue scriptEngineRequestQueue;

    @Inject
    private ServiceFinderBeanProvider serviceFinderBeanProvider;

//    @Inject
//    private SynchronousCommandExecutorMonitoring synchronousCommandExecutorMonitoring;

    private static final String USER_ID_CONTEXT_VALUE_NAME = "X-Tor-UserID";

    @SuppressWarnings({"squid:CallToDeprecatedMethod","squid:S1181"})
    public List<AbstractDto> processCommandRequest(final CommandRequest  commandRequest, final String requestId) {
        String command = null;
        List<AbstractDto> dtos = new ArrayList<>();
        CommandResponseDto commandResponseDto = new CommandResponseDto();
        try {
            setUserContext(requestId);
            command = commandRequest.getCommandSet() + " " + commandRequest.getCommandWithArguments();
            logger.debug("jms:/queue/scriptengine/request operation=receive, requestId={}, command={}", requestId,
                    command);
            setUserContext(commandRequest);
            commandResponseDto = processRequest(commandRequest);

        } catch (final UnrecognisedCommandException e) {
            logger.debug("processCommandRequest commandSet = {}  requestId = {}  received UnrecognisedCommandException ", commandRequest.getCommandSet(),requestId);
            commandResponseDto = errorManager.handleUnrecognisedCommand(command);
 //           dispatchCommandResponseDtoWithTerminate(commandResponseDto);
        } catch (final DatabaseNotAvailableException e) {
            logger.debug("processCommandRequest commandSet = {}  requestId = {}  received DataBaseNotAvailableException ", commandRequest.getCommandSet(),requestId);
            commandResponseDto = errorManager.handleDatabaseNotAvailableException(command);
 //           dispatchCommandResponseDtoWithTerminate(commandResponseDto);
        } catch (final Exception|Error e) {
            logger.debug("processCommandRequest commandSet = {}  requestId = {}  received Exception = {}", commandRequest.getCommandSet(), requestId, e.getMessage());
            commandResponseDto = errorManager.handleUnexpectedException(e, command);
 //           dispatchCommandResponseDtoWithTerminate(commandResponseDto);
        } finally {
            clearUserContext();
            Command commanddd = toCommand(commandRequest);
            dtos = toDtos(commanddd, commandResponseDto);
            return dtos;
        }
    }

    private CommandResponseDto processRequest(final CommandRequest commandRequest) {
        Command command = toCommand(commandRequest);
        logger.debug("command : {} {}   -- RequestId={}", commandRequest.getCommandSet(), commandRequest.getCommandWithArguments(),
                commandRequest.getRequestId());
            if (SynchronousCommandSet.isSynchronousCommand(command.getCommandContext())) {
                return executeCommandSynchronously(commandRequest.getRequestId(), command);
            } else {
                logger.error("FAKE SCRIPT-ENGINE  wrong command context = {}",command.getCommandContext());
                return null;
//                command = updateCommandRequestIfAlias(commandRequest, command);
//                Channel channel = scriptEngineRequestQueue.getChannelForCommandSet(command);
//                if (commandSetHasJmsQueue(channel)) {
//                    scriptEngineRequestQueue.sendCommandAsynchronously(commandRequest, command, channel);
//                } else {
//                    executeCommandSynchronously(commandRequest.getRequestId(), command);
//                }
            }
    }

//    private Command updateCommandRequestIfAlias(final CommandRequest commandRequest, Command command) {
//        if (aliasHandler.isAlias(command)) {
//            command = aliasHandler.resolveAlias(command);
//            updateCommandRequest(commandRequest, command);
//        }
//        return command;
//    }


//    private void dispatchCommandResponseDtoWithTerminate(final CommandResponseDto commandResponseDto) {
//        final String requestId = getRequestId();
//        final List<AbstractDto> dtos = new ArrayList<>(commandResponseDto.getResponseDto().getElements());
//        if (isStreamedOrFileRequest(requestId)) {
//            dtos.add(SummaryDto.fromCommandResponseDto(commandResponseDto, requestId));
//        }
//        commandRouter.printLinesAndTerminate(requestId, dtos.toArray(new AbstractDto[dtos.size()]));
//    }

    @SuppressWarnings("squid:CallToDeprecatedMethod")
    private void setUserContext(final CommandRequest commandRequest) {
        contextService.setContextValue(USER_ID_CONTEXT_VALUE_NAME, commandRequest.getUserId());
    }

    private void setUserContext(final String requestId) {
        contextService.setContextValue(COMMAND_REQUEST_CONTEXT_ID, requestId);
    }

    private String getRequestId() {
        return contextService.getContextValue(COMMAND_REQUEST_CONTEXT_ID);
    }

    private void clearUserContext() {
        contextService.setContextValue(USER_ID_CONTEXT_VALUE_NAME, null);
        contextService.setContextValue(COMMAND_REQUEST_CONTEXT_ID, null);
    }

//    @SuppressWarnings("squid:CallToDeprecatedMethod")
//    private void updateCommandRequest(final CommandRequest commandRequest, final Command command) {
//        final String aliasedCommandString = command.getCommandContext() + ' ' + command.getCommand();
//        logger.debug("updateCommandRequest from \"{}\" to alias \"{}\"", commandRequest.getCommandWithArguments(), aliasedCommandString);
//        final CommandRequest commandRequestForAlias = CommandRequest.fromCommandString(aliasedCommandString);
//        commandRequest.setCommand(commandRequestForAlias.getCommand());
//        commandRequest.setCommandSet(commandRequestForAlias.getCommandSet());
//        commandRequest.setCommandWithArguments(commandRequestForAlias.getCommandWithArguments());
//    }

    private CommandResponseDto executeCommandSynchronously(final String requestId, final Command command) {
//        List<AbstractDto> dtos = new ArrayList<>();
//        try {
 //           synchronousCommandExecutorMonitoring.startCommand(requestId,command.getCommandContext());
            logger.debug("executeCommandSynchronous, requestId={}, command={} {}", requestId, command.getCommandContext(), command.getCommand());
            final CommandHandler commandHandler = getCommandHandler(command.getCommandContext());
            logger.debug("executeCommandSynchronous, requestId={}  commandContext={} ask for execute", requestId, command.getCommandContext());
            final CommandResponseDto commandResponseDto = commandHandler.execute(command);
            return commandResponseDto;
//            dtos = toDtos(command, commandResponseDto);
//
//
//            logger.debug("executeCommandSynchronous, requestId={}, responseSize={} statusCode{}", requestId, dtos.size(),
//                    commandResponseDto.getStatusCode());
//
//            addSummeryDtoIfStreamingRequest(requestId, commandResponseDto, dtos);
//            commandRouter.printLines(requestId, dtos.toArray(new AbstractDto[dtos.size()]));

//        } catch (final IllegalStateException illegalStateException) {
//            logger.error("executeCommandSynchronous - commandContext={} - received IllegalStateException exception {}", command.getCommandContext(), illegalStateException.getMessage());
//            errorHandler.printStackTraceIfEnable(illegalStateException);
//            throw new UnrecognisedCommandException(command);
//        } catch (final Exception exception) {
//            logger.error("executeCommandSynchronous - commandContext={} - received Exception exception {}", command.getCommandContext(), exception.getMessage());
//            errorHandler.printStackTraceIfEnable(exception);
//            throw exception;
//        } finally {
//            synchronousCommandExecutorMonitoring.stopCommand(requestId);
//            if (! isStreamed(requestId)) {
//                commandRouter.terminateProcess(requestId, 0, dtos.size());
//            }
//        }
    }

//    private boolean commandSetHasJmsQueue(final Channel channel) {
//        return channel != null;
//    }
//
    private List<AbstractDto> toDtos(final Command command, final CommandResponseDto commandResponseDto) {
        final List<AbstractDto> dtos = new ArrayList<>(commandResponseDto.getResponseDto().getElements());
        insertCommandDto(command, dtos);
        return dtos;
    }

    private void addSummeryDtoIfStreamingRequest(final String requestId, final CommandResponseDto commandResponseDto, final List<AbstractDto> dtos) {
        if (isStreamedOrFileRequest(requestId)) {
            // Add summaryDto WITH requestId if set as true in the commandResponseDto
            if (commandResponseDto.isLogViewerCompatible()) {
                final String logReference = commandResponseDto.getLogReference() == null ? requestId : commandResponseDto.getLogReference();
                dtos.add(SummaryDto.fromCommandResponseDto(commandResponseDto, logReference));
            } else {
                dtos.add(SummaryDto.fromCommandResponseDto(commandResponseDto));
            }
        }
    }

    private boolean isStreamed(final String requestId) {
        return requestId.startsWith("st:");
    }

    private boolean isStreamedOrFileRequest(final String requestId) {
        return requestId.startsWith("st:") || requestId.startsWith("file:");
    }

    private void insertCommandDto(final Command command, final List<AbstractDto> dtos) {
        dtos.add(0, new CommandDto(command.getCommandContext() + " " + command.getCommand()));
    }

    private CommandHandler getCommandHandler(final String commandSet) {
//        if (ALIAS.equals(commandSet)) {
//            return aliasHandler;
//        }
        return serviceFinderBeanProvider.getServiceFinderBean().find(CommandHandler.class, commandSet);
    }

    @SuppressWarnings("squid:CallToDeprecatedMethod")
    private Command toCommand(final CommandRequest commandRequest) {
        final String commandSet = commandRequest.getCommandSet();
        final Command command = new Command(commandSet, commandRequest.getCommandWithArguments());

        final String filePath = commandRequest.getFilePath();
        final String fileName = commandRequest.getFileName();
        command.getProperties().put("filePath", filePath);
        command.getProperties().put("fileName", fileName);

        /*
         * TODO eeitsik, emulleo TECHNICAL DEBT BY SECADM Need to get rid of
         * this hard-coded check, discuss with Team responsible for "secadm"!
         */
        if (isCommandSetUsingLegacyFileHandling(commandSet) && !Strings.isNullOrEmpty(filePath)) {
            addFileAsByteArrayToProperties(command, filePath);
        }

        return command;
    }

    private void addFileAsByteArrayToProperties(final Command command, final String filePath) {
        try {
            final FileInputStream fileInputStream = new FileInputStream(new File(filePath));
            command.getProperties().put("file:", ByteStreams.toByteArray(fileInputStream));
        } catch (final IOException e) {
            // Depending on implementation of secadm/shm to handle if NO file
            // property present!
            logger.error("addFileAsByteArrayToProperties Exception : {}",e.getMessage());
        }
    }

    private boolean isCommandSetUsingLegacyFileHandling(final String commandSet) {
        return commandSet.equals("secadm");
    }
}
