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

import javax.enterprise.inject.Instance

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.cds.cdi.support.spock.CdiSpecification

import com.ericsson.oss.services.cm.admin.cli.handler.DefaultCommandHandler
import com.ericsson.oss.services.cm.admin.cli.handler.ViewCommandHandler
import com.ericsson.oss.services.cm.admin.cli.handler.ModifyCommandHandler

class CliCommandHandlerFactorySpec extends CdiSpecification {

    @ObjectUnderTest
    CliCommandHandlerFactory cliCommandHandlerFactory

    @ImplementationInstance
    private Instance<CliCommandHandler> cliCommandHandlers = Mock();

    private final Collection<CliCommandHandler> handlers = new ArrayList<>();


    def 'Given clicomand, command handler returned '() {
        given: 'command input'
        handlers.add(new ViewCommandHandler());
        handlers.add(new ModifyCommandHandler());
        handlers.add(new DefaultCommandHandler());

        CliCommand cliCommand = new CliCommand(command)
        cliCommandHandlers.iterator() >> handlers.iterator()

        when: 'get handler'
        CliCommandHandler getHandler = cliCommandHandlerFactory.getHandler(cliCommand.getOperation(),cliCommand.getSubCommand())

        then: 'handler returned'

        getHandler.getClass().getName() == handler

        where:
        command                   | handler
        "admin parameter view"    | "com.ericsson.oss.services.cm.admin.cli.handler.ViewCommandHandler"
        "admin parameter modify"  | "com.ericsson.oss.services.cm.admin.cli.handler.ModifyCommandHandler"
        "admin test"              | "com.ericsson.oss.services.cm.admin.cli.handler.DefaultCommandHandler"
        "admin parameter delete"  | "com.ericsson.oss.services.cm.admin.cli.handler.DefaultCommandHandler"
    }
}
