package com.ericsson.oss.services.cm.alias

import com.ericsson.cds.cdi.support.rule.ImplementationClasses
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.itpf.datalayer.dps.stub.RuntimeConfigurableDps
import com.ericsson.oss.itpf.sdk.context.ContextService
import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean
import com.ericsson.oss.itpf.sdk.eventbus.Channel
import com.ericsson.oss.itpf.sdk.eventbus.ChannelLocator
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder
import com.ericsson.oss.services.cli.alias.model.CliAlias
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl
import com.ericsson.oss.services.scriptengine.api.ServiceFinderBeanProvider
import com.ericsson.oss.services.scriptengine.spi.CommandHandler
import com.ericsson.oss.services.scriptengine.spi.dtos.Command
import com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus
import com.ericsson.oss.services.cm.alias.events.dps.DatabaseStatus
import spock.lang.Unroll

import javax.inject.Inject

class AliasSpec extends CdiSpecification {

    @ObjectUnderTest
    AliasHandler objUnderTest

    @ImplementationClasses
    def classes = [ErrorHandlerImpl]

    @Inject
    ContextService contextServiceMock

    @Inject
    AliasDao aliasDao

    @Inject
    ChannelLocator channelLocatorMock

    @MockedImplementation
    ServiceFinderBeanProvider serviceFinderBeanProviderMock

    @MockedImplementation
    DatabaseStatus databaseStatusMock

    def serviceFinderBeanMock = Mock(ServiceFinderBean)

    def setup() {
        serviceFinderBeanProviderMock.getServiceFinderBean() >> serviceFinderBeanMock
        serviceFinderBeanMock.findAll(CommandHandler, _ as String) >> []
        databaseStatusMock.isAvailable() >> true
    }


    def 'can create simple alias command'() {
        given: 'a simple alias create command'
            def command = new Command('alias', '"aliasName $1" "commandSet arg1 $1"', [:])

        and: 'the user is set in the context service'
            1 * contextServiceMock.getContextValue('X-Tor-UserID') >> 'someUser'

        when: 'execute command to create alias'
            def response = objUnderTest.execute(command)

        then: 'the response is successful'
            ResponseStatus.SUCCESS == response.getStatusCode()
            AliasHandler.ALIAS_CREATE_SUCCESS_MESSAGE == response.getStatusMessage()

        and: 'the alias exists in the database'
            aliasDao.isDefinedAlias('aliasName')

        and: 'the alias can be resolved with the correct user Id'
            CliAlias cliAlias = aliasDao.getAlias('aliasName')
            cliAlias.userId == 'someUser'
    }

    def 'executing a non aliased command does not resolve any alias from the database'() {
        given: 'a simple alias is created'
            objUnderTest.execute(new Command('alias', '"aliasName $1" "commandSet arg1 $1"', [:]))

        when: 'isAlias is called for an un aliased command'
            def response = objUnderTest.isAlias(new Command('command', 'with arguments', [:]))

        then: 'the response is false'
            !response

        and: 'the alias did exists in the database'
            aliasDao.isDefinedAlias('aliasName')
    }

    @Unroll
    def 'creating alias for command \'#commandString\' with wrong arguments returns invalid arguments error'() {
        given: 'an alias create command with invalid command specifying a file'
            def command = new Command('alias', commandString, [:])

        when: 'execute command to create alias'
            def response = objUnderTest.execute(command)

        then: 'the response is unsuccessful'
            ResponseStatus.COMMAND_SYNTAX_ERROR == response.getStatusCode()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_ERROR_CODE == response.getErrorCode()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_ERROR_MSGS.first() == response.getErrorMessage()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_ERROR_MSGS.last() == response.getSolution()

        where: 'the following alias commands are executed'
            commandString                             | _
            '"aliasName $1 $2 $1" "command $1 $2"'    | _
            '"aliasName $1 $2 $4" "command $1 $2 $4"' | _
            '"aliasName $2 $3 $4" "command $2 $3 $4"' | _
            '"aliasName $1 $2 $3" "command $1 $2"'    | _
            '"aliasName $1 $2" "command $1 $2 $3"'    | _
    }

    @Unroll
    def 'creating alias named "existingCommandSet" that is an existing CommandSet and #explanation returns invalid create with command set error'() {
        given: 'an alias create command with invalid command specifying a file'
            def command = new Command('alias', '"existingCommandSet $1 " "existingCommandSet $1"', [:])

        when: 'execute command to create alias'
            def response = objUnderTest.execute(command)

        then: 'the Channel Locator or the Service Finder were called for the existingCommandSet'
            if (mockQueue) {
                1 * channelLocatorMock.lookupChannel('jms:/queue/commandHandler.existingCommandSet') >> Mock(Channel)
            } else {
                1 * serviceFinderBeanMock.findAll(CommandHandler, 'existingCommandSet') >> [1]
            }

        then:  'the response is unsuccessful'
            ResponseStatus.COMMAND_SYNTAX_ERROR == response.getStatusCode()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_CODE == response.getErrorCode()
            'Cannot create alias with name "existingCommandSet" as it is a CLI Command Set' == response.getErrorMessage()

        where: 'either the queue is defined, or the service is defined'
            mockQueue | explanation
            true      | 'the channel URI "commandHandler.existingCommandSet" is defined'
            false     | 'the CommandHandler has an implementation for "existingCommandSet"'
    }

    @Unroll
    def 'creating alias for command \'#commandString\' with wrong syntax returns invalid syntax error'() {
        given: 'an alias create command with invalid command specifying a file'
            def command = new Command('alias', commandString, [:])

        when: 'execute command to create alias'
            def response = objUnderTest.execute(command)

        then: 'the response is unsuccessful'
            ResponseStatus.COMMAND_SYNTAX_ERROR == response.getStatusCode()
            ErrorHandlerImpl.ALIAS_SYNTAX_ERROR_CODE == response.getErrorCode()
            ErrorHandlerImpl.ALIAS_SYNTAX_ERROR_MSGS.first() == response.getErrorMessage()
            ErrorHandlerImpl.ALIAS_SYNTAX_ERROR_MSGS.last() == response.getSolution()

        where: 'the following alias commands are executed'
            commandString                               | _
            '"aliasName $1 $2 $1"'                      | _
            '"aliasName $0 $1 $2" "command $0 $1 $2"'   | _
            '"aliasName $-1 $1 $2" "command $-1 $1 $2"' | _
            '"aliasName $1 $2 $10" "command $1 $2 $10"' | _
            '"     aliasName" "command"'                | _
            '"aliasName" "      command"'               | _
    }

    def 'creating alias that already exists returns correct error'() {
        given: 'a simple alias is created'
            def command = new Command('alias', '"aliasName $1" "commandSet arg1 $1"', [:])
            objUnderTest.execute(command)

        when: 'execute command to create alias of the same name again'
            def response = objUnderTest.execute(command)

        then: 'the response is unsuccessful'
            ResponseStatus.COMMAND_SYNTAX_ERROR == response.getStatusCode()
            ErrorHandlerImpl.ALIAS_ALREADY_EXISTS_ERROR_CODE == response.getErrorCode()
            ErrorHandlerImpl.ALIAS_ALREADY_EXISTS_ERROR_MSGS.first().replace('{0}', 'aliasName') == response.getErrorMessage()
            ErrorHandlerImpl.ALIAS_ALREADY_EXISTS_ERROR_MSGS.last() == response.getSolution()
    }

    @Unroll
    def 'cannot create alias command for command \'#commandString\' due to alias create with file error'() {
        given: 'an alias create command with invalid command specifying a file'
            def command = new Command('alias', commandString, [:])

        when: 'execute command to create alias'
            def response = objUnderTest.execute(command)

        then: 'the response is unsuccessful'
            ResponseStatus.COMMAND_SYNTAX_ERROR == response.getStatusCode()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_WITH_FILE_ERROR_CODE == response.getErrorCode()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_WITH_FILE_ERROR_MSGS.first() == response.getErrorMessage()
            ErrorHandlerImpl.ALIAS_INVALID_CREATE_WITH_FILE_ERROR_MSGS.last() == response.getSolution()

        where: 'the following alias commands are executed'
            commandString                                                          | _
            '"aliasWithFile $1" "command with file:$1"'                            | _
            '"aliasWithFile $1" "command with file: $1 --and some --extra --attr"' | _
            '"aliasWithFile $1" "command with --some attr file:    $1"'            | _
    }

    @Unroll
    def 'using alias \'#aliasName #aliasArgs\' for \'#aliasedCommandString\' when executing \'#aliasName #commandArgs\' returns \'#expectedCommand\''() {
        given: 'the alias is created'
            def aliasCreateCommand = new Command('alias', "\"$aliasName $aliasArgs\" \"$aliasedCommandString\"", [:])
            objUnderTest.execute(aliasCreateCommand)

        and: 'the alias exists in the database'
            def command = new Command(aliasName, "$commandArgs")
            objUnderTest.isAlias(command)

        when: 'the alias is resolved from the cache'
            def result = objUnderTest.resolveAlias(command)

        then: 'the correct command string is stored in the result'
            "${result.commandContext} ${result.command}" == expectedCommand

        where: 'the following aliases are created, the alias commands are executed and the expected result is correct'
            aliasName    | aliasArgs  | aliasedCommandString              | commandArgs      || expectedCommand
            'aliasName1' | ''         | 'command'                         | ''               || 'command '
            'aliasName1' | ''         | 'command'                         | '     '          || 'command '
            'aliasName2' | '$1'       | 'command $1'                      | 'arg1'           || 'command arg1'
            'aliasName3' | '$1 $2'    | 'command $1 $2'                   | 'arg1 arg2'      || 'command arg1 arg2'
            'aliasName4' | '$1'       | 'command $1 $1'                   | 'arg1'           || 'command arg1 arg1'
            'aliasName5' | '$1 $2 $3' | 'command $1 $3 $1 $3 $2'          | 'arg1 arg2 arg3' || 'command arg1 arg3 arg1 arg3 arg2'
            'aliasName5' | '$1 $2 $3' | 'command $1 $2 $3 $1 $2 $3 $2 $1' | 'arg1 arg2 arg3' || 'command arg1 arg2 arg3 arg1 arg2 arg3 arg2 arg1'
    }

}