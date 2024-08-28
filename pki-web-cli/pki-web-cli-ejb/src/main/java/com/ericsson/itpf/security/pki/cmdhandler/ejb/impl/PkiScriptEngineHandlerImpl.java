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

package com.ericsson.itpf.security.pki.cmdhandler.ejb.impl;

import java.util.ArrayList;

import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.PkiWebCliService;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.mapper.PkiToSEResponseMapper;
import com.ericsson.itpf.security.pki.cmdhandler.util.DownloadFileHolder;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.recording.classic.SystemRecorderBean;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;
import com.ericsson.oss.services.scriptengine.spi.FileDownloadHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.*;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.InMemoryFileDto;

/**
 * Implementation for ScriptEngine CommandHandler, and gateway for web-cli command for PKIADM
 * 
 * 
 * @author xsumnan on 29/03/2015.
 */

@Stateless
@EServiceQualifier(PkiCommand.APP_ID)
@TransactionManagement(TransactionManagementType.CONTAINER)
public class PkiScriptEngineHandlerImpl implements CommandHandler, FileDownloadHandler {

    private static final String PKIADM_COMMAND_PREFIX = PkiCommand.APP_ID.toUpperCase() + " ";
    public static final String GOT_ERROR_FROM_PKI_SERVICE = "Got error from PkiCLIService.";

    @Inject
    Logger logger;

    @EServiceRef
    private PkiWebCliService pkiWebCliService;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    private PkiToSEResponseMapper pkiToSEResponseMapper;

    private final SystemRecorder systemRecorder = new SystemRecorderBean();

    /**
     * method which start processing of Command.
     *
     * @param Command
     *
     * @return CommandResponseDto
     */

    @Override
    @Authorize(resource = PkiCommand.APP_ID, action = "execute", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public CommandResponseDto execute(final Command command) {

        final CommandResponseDto commandResponseDto = new CommandResponseDto();

        final ResponseDto pkiResponseDto = new ResponseDto(new ArrayList<AbstractDto>());

        PkiCommandResponse commandResponse = null;

        PkiCliCommand cliCommand = null;

        String commandName = null;

        try {
            cliCommand = new PkiCliCommand(command.getCommand());
            if (command.getProperties() != null) {
                cliCommand.setProperties(command.getProperties());
            }
            commandName = "pkiadm " + cliCommand.getCommandText();
            this.systemRecorder.recordCommand(commandName, CommandPhase.STARTED, "CLI Operation", "PKI-Credentials", "Command execution started ");
            commandResponse = pkiWebCliService.processCommand(cliCommand);
            logger.info("Command executed successfully preparing response : {} ", commandName);
            pkiToSEResponseMapper.convertToCommandResponseDto(pkiResponseDto, commandResponse);
            pkiToSEResponseMapper.setSummaryForMessageCommandResponse(commandResponse, commandResponseDto);
            if (commandResponseDto.getErrorCode() > 0) {
                this.systemRecorder.recordCommand(commandName, CommandPhase.FINISHED_WITH_ERROR, "CLI Operation", "PKI-Credentials", "Command execution failed");
            } else {
                this.systemRecorder.recordCommand(commandName, CommandPhase.FINISHED_WITH_SUCCESS, "CLI Operation", "PKI-Credentials", "Command execution completed succesfully");
            }

        } catch (final PkiWebCliException se) {
            final String errorMessage = "Error " + se.getErrorCode() + " : " + se.getMessage();
            final String suggestedSolution = " Suggested Solution : " + se.getSuggestedSolution();
            commandResponse = new PkiMessageCommandResponse(errorMessage + suggestedSolution, se.getErrorCode(), se.getMessage(), suggestedSolution);
            pkiToSEResponseMapper.constructMessageResponse(pkiResponseDto, errorMessage, suggestedSolution);
            pkiToSEResponseMapper.setSummaryForMessageCommandResponse(commandResponse, commandResponseDto);
            this.systemRecorder.recordCommand(commandName, CommandPhase.FINISHED_WITH_ERROR, "CLI Operation", "PKI-Credentials", "Command execution failed with " + errorMessage + suggestedSolution);
            logger.error(GOT_ERROR_FROM_PKI_SERVICE, se);
        } catch (final Exception e) {
            commandResponse = new PkiMessageCommandResponse(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, PkiWebCliException.ERROR_CODE_START_INT + PkiWebCliException.ErrorType.UNEXPECTED_ERROR.toInt(),
                    PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
            pkiToSEResponseMapper.createErrorCommandResponse(pkiResponseDto);
            pkiToSEResponseMapper.setSummaryForMessageCommandResponse(commandResponse, commandResponseDto);
            logger.error("Got unexpected error from pkiService.", e);
            this.systemRecorder.recordCommand(commandName, CommandPhase.FINISHED_WITH_ERROR, "CLI Operation", "PKI-Credentials", "Command execution failed with unexpected exception" + e.toString());
        }

        commandResponseDto.setCommand(PKIADM_COMMAND_PREFIX + command.getCommand());
        commandResponseDto.setResponseDto(pkiResponseDto);
        logger.info("Returning {} response to script-engine for command {}", commandResponseDto, commandName);
        return commandResponseDto;
    }

    /**
     * method which gives response for the file download
     *
     * @param fileId
     *
     * @return inMemoryFileDto
     */

    @Override
    @Authorize(resource = PkiCommand.APP_ID, action = "execute", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public FileDownloadResponseDto execute(final String fileId) {
        logger.info("download request from script-engine key: {} ", fileId);
        InMemoryFileDto inMemoryFileDto = null;
        try {
            final DownloadFileHolder downloadFileHolder = (DownloadFileHolder) exportedItemsHolder.fetch(fileId);
            if (downloadFileHolder == null) {
                throw new IllegalArgumentException("file content is not found with key " + fileId);
            }
            if (downloadFileHolder.isDeletable()) {
                // adding to avoid deletion of entry due to two calls
                exportedItemsHolder.remove(fileId);
                logger.info("content deleted from map with id:{}", fileId);
            } else {
                logger.info("setting content to be deleted from map with id: {}", fileId);
                ((DownloadFileHolder) exportedItemsHolder.fetch(fileId)).setDeletable(true);
            }
            inMemoryFileDto = new InMemoryFileDto(downloadFileHolder.getContentToBeDownloaded(), downloadFileHolder.getFileName(), downloadFileHolder.getContentType());
        } catch (final Exception e) {
            logger.debug("Error occurred while downloading the file", e);
            logger.error(e.getMessage());
        }
        return inMemoryFileDto;
    }

}
