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

package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus;

@Stateless
@EServiceQualifier("dummy")
public class DummyCommandHandler implements CommandHandler {

    @Inject
    ContextService contextService;

    @Override
    public CommandResponseDto execute(final Command command) {
        final CommandResponseDto dummyResponseDto = new CommandResponseDto();

        if (command.getCommand().contains("error")) {
            dummyResponseDto.setStatusCode(ResponseStatus.COMMAND_EXECUTION_ERROR);
            dummyResponseDto.setErrorMessage("Command Execution Failed");
            dummyResponseDto.setErrorCode(9999);
            dummyResponseDto.setSolution("some solution");
            dummyResponseDto.addErrorLines();
        } else if (command.getCommand().contains("who")) {
            dummyResponseDto.setStatusCode(ResponseStatus.SUCCESS);
            final String userId = contextService.getContextValue("X-Tor-UserID");
            System.out.println(" USER_ID = "+userId);
            dummyResponseDto.setStatusMessage(userId);
            dummyResponseDto.addSuccessLines();
        } else {
            dummyResponseDto.setStatusCode(ResponseStatus.SUCCESS);
            dummyResponseDto.setStatusMessage("Command Executed Successfully");
            dummyResponseDto.addSuccessLines();
        }
        return dummyResponseDto;
    }

    public void setContextServiceStub(final ContextService stub) {
        // Required for testing purposes
        contextService = stub;
    }

}
