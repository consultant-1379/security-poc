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
 -----------------------------------------------------------------------------*/

package com.ericsson.oss.services.cm.admin.cli;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.recording.classic.SystemRecorderNonCDIImpl;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.services.cm.error.ErrorManager;
import com.ericsson.oss.services.cm.error.exception.UnauthorizedServiceAccessException;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

/**
 * This class is responsible for handling of admin CLI commands
 */
@Stateless
@EServiceQualifier("admin")
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class ApplicationParameterCli implements CommandHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final SystemRecorder recorder = new SystemRecorderNonCDIImpl(); // NOPMD
    private static final String SNMPV3_SECURITY_CONFIGURATION_MR_ID = "105 65-0334/63480";

    @Inject
    private ErrorManager errorManager;

    @Inject
    private CliCommandHandlerFactory cliCommandHandlerFactory;

    /**
     * Execute the input {@link Command}, and returns a {@link CommandResponseDto} to the CLI.
     *
     * @param spiCommand
     *            the input command
     * @return the CLI response
     */
    @Override
    public CommandResponseDto execute(final Command spiCommand) {
        final String fullCommand = spiCommand.getCommandContext().trim() + " " + spiCommand.getCommand().trim();
        try {
            final CliCommand cliCommand = new CliCommand(fullCommand);
            recordMRExecution(SNMPV3_SECURITY_CONFIGURATION_MR_ID);
            logger.debug("Process admin command");
            final CliCommandHandler cliCommandHandler = cliCommandHandlerFactory.getCliCommandHandler(cliCommand);
            return cliCommandHandler.processCommand(cliCommand);
        } catch (final UnauthorizedServiceAccessException e) {
            logger.debug("CLI command {}: {}", fullCommand, e.getMessage());
            return errorManager.handleAccessUnauthorizedException();
        }
    }

    /**
     * Records event in DDP for MR statistics.
     *
     * @param mrId
     *
     */
    private void recordMRExecution(final String mrId) {
        final Map<String, Object> dataEvent = new HashMap<>();
        dataEvent.put("MR", mrId);
        recorder.recordEventData("MR.EXECUTION", dataEvent);
    }
}