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
package com.ericsson.oss.services.cm.admin.cli.parser

import javax.inject.Inject

import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.cli.handler.ViewCommandHandler
import org.apache.commons.cli.CommandLine
import org.apache.commons.cli.ParseException

class ExtendedCommandParserSpec extends CdiSpecification {
    @Inject
    ExtendedCommandParser extendedCommandParser

    @Inject
    ViewCommandHandler viewComandHandler



    def 'invalid parameter arguments given, parser exception thrown '() {

        given: 'command input'

        when: 'execute command'
        extendedCommandParser.parse(viewComandHandler.getCommandOptions(), parmArg)

        then: 'response returned'
        thrown(ParseException)

        where:
        parmArg << [
            ["--name", "t", "a"] as String[],
            ["--name"] as String[],
            ["-name"] as String[],
            ["--test", "b"] as String[],
            ["a", "b"] as String[]
        ]
    }

    def 'valid parameter arguments given, command line return '() {
        given: 'command input'

        when: 'execute command'
        CommandLine commandLine = extendedCommandParser.parse(viewComandHandler.getCommandOptions(), parmArg)

        then: 'response returned'
        commandLine.hasOption("name") == true
        commandLine.getOptionValue("name") == value

        where:
        parmArg                                               | value
        ["--name", "t"] as String[]                           | "t"
        [
            "--name",
            "NODE_SNMP_SECURITY"] as String[]                 | "NODE_SNMP_SECURITY"
        [
            "--name",
            "NODE_SNMP_INIT_SECURITY"] as String[]            | "NODE_SNMP_INIT_SECURITY"
    }
}