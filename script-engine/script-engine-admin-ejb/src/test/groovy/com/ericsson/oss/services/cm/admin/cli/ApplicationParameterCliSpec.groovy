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
package com.ericsson.oss.services.cm.admin.cli

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;

class ApplicationParameterCliSpec extends CdiSpecification {

    @ObjectUnderTest
    ApplicationParameterCli applicationParameterCli

    @ImplementationInstance
    CliCommandHandlerFactory cliCommandHandlerFactoryMock  = Mock(CliCommandHandlerFactory)

    @MockedImplementation
    CliCommandHandler cliCommandHandlerMock;

    def command = Mock(Command)

    final String commandContext = "admin"

    def 'Execute command, response returned '() {
        given: 'command input'
        command.getCommandContext() >> commandContext
        command.getCommand() >> commandName
        cliCommandHandlerFactoryMock.getCliCommandHandler(_) >> cliCommandHandlerMock

        when: 'execute command'
        applicationParameterCli.execute(command)

        then: 'response returned'
        1 * cliCommandHandlerMock.processCommand(_)

        where:
        commandName << [
            "parameter view --name t t",
            "parameter view",
            "para vie",
            "parameter modify",
            "parameter modify --name t t",
            "para mod"
        ]
    }
}



