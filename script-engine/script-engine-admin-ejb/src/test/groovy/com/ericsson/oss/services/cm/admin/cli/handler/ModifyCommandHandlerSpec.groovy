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
package com.ericsson.oss.services.cm.admin.cli.handler

import com.ericsson.oss.services.cm.error.ErrorHandlerImpl

import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.PARAMETER_UPDATE_FAILURE_ERROR_CODE
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.PARAMETER_VALUE_INVALID_ERROR_CODE
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.SYNTAX_ERROR_CODE
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_EXECUTION_ERROR
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_SYNTAX_ERROR
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.SUCCESS;

import javax.inject.Inject

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.cli.CliCommand
import com.ericsson.oss.services.cm.admin.cli.parser.ExtendedCommandParser
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationService
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper
import com.ericsson.oss.services.cm.admin.validation.ParametersValidationFactory
import com.ericsson.oss.services.cm.admin.validation.ValidationResult;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto

class ModifyCommandHandlerSpec extends CdiSpecification {
    @Inject
    private ModifyCommandHandler modifyCommandHandler;

    @Inject
    private ErrorHandlerImpl errorHandler

    @Inject
    private ExtendedCommandParser extendedCommandParser = Mock();

    @ImplementationInstance
    private ConfigurationService configurationService = Mock(ConfigurationService);

    @ImplementationInstance
    private PasswordHelper passwordHelper = Mock();

    @ImplementationInstance
    private ParametersValidationFactory parametersValidationFactory = Mock();


    def 'Valid Modify command for SNMP params, success response returned'() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        parametersValidationFactory.validateSnmpData(_) >> ValidationResult.ok("")
        parametersValidationFactory.validateAuditTime(_) >> ValidationResult.ok("")

        passwordHelper.encryptEncode(_) >> "encryptedPasswordpass"
        configurationService.updateParameter(_) >> true

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode

        where:
        fullCommand                                                                                                                                                                                       | returnCode
        "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {securityLevel:auth_priv,authProtocol:MD5,authPassword:password,privProtocol:DES,privPassword:password,user:user}"                 | SUCCESS
        "admin parameter modify --name NODE_SNMP_SECURITY --value {securityLevel:NO_AUTH_NO_PRIV,authProtocol:NONE,authPassword:Password123,privProtocol:NONE,privPassword:Password456,user:defaultuser}" | SUCCESS
        "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {securityLevel:auth_no_priv,authProtocol:sha1,authPassword:password,privProtocol:privPassword:des,pass?word,user:user}"            | SUCCESS
        "admin parameter modify --name NODE_SNMP_SECURITY --value {securityLevel:AUTH_PRIV,authProtocol:MD5,authPassword:test12345,privProtocol:DES,privPassword:TEST12345,user:user}"                    | SUCCESS
        "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {securityLevel:auth_priv,authProtocol:MD5,authPassword:pass@12345,privProtocol:DES,privPassword:xword@12345,user:user}"            | SUCCESS
        "admin parameter modify --name AP_SNMP_AUDIT_TIME --value 04:30"                                                                                                                                  | SUCCESS
        "admin parameter modify --name AP_SNMP_AUDIT_TIME --value 66:78"                                                                                                                                  | SUCCESS
    }

    def 'Valid Modify command for service scoped parameter, success response returned'() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        parametersValidationFactory.validateData(_) >> ValidationResult.ok("")

        passwordHelper.encryptEncode(_) >> "encryptedPasswordpass"
        configurationService.updateParameter(_) >> true

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode

        where:
        fullCommand                                                                                                                                                                                       | returnCode
        "admin parameter modify --name jndiBind --value mediation-service-mssnmpfm-6d79bc5797 --service_identifier myService"                                                                                                                                  | SUCCESS
    }

    def 'Valid Modify command for jvm scoped parameter, success response returned'() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        parametersValidationFactory.validateData(_) >> ValidationResult.ok("")

        passwordHelper.encryptEncode(_) >> "encryptedPasswordpass"
        configurationService.updateParameter(_) >> true

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode

        where:
        fullCommand                                                                                                                                                                                       | returnCode
        "admin parameter modify --name jndiBind --value mediation-service-mssnmpfm-6d79bc5797 --app_server_identifier myService"                                                                                                                                  | SUCCESS
    }

    def 'Valid Modify command for both service and jvm scoped parameter, success response returned'() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        parametersValidationFactory.validateData(_) >> ValidationResult.ok("")

        passwordHelper.encryptEncode(_) >> "encryptedPasswordpass"
        configurationService.updateParameter(_) >> true

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode

        where:
        fullCommand                                                                                                                                                                                       | returnCode
        "admin parameter modify --name jndiBind --value mediation-service-mssnmpfm-6d79bc5797 --service_identifier myService --app_server_identifier myService"                                                                                                                                  | SUCCESS
    }

    def 'Valid Modify command for non-SNMP params, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        parametersValidationFactory.validateData(_) >> ValidationResult.ok("")
        configurationService.updateParameter(_) >> true

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode

        where:
        fullCommand                                                                                                                            | returnCode
        "admin parameter modify --name aiAccount --value abc"                                                                                  | SUCCESS
        "admin parameter modify --name pmicSupportedRopPeriods --value [ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR,ONE_DAY]" | SUCCESS
        "admin parameter modify --name pmicSupportedRopPeriods --value [ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR]"         | SUCCESS
        "admin parameter modify --name pmicSupportedRopPeriods --value [ONE_MIN]"                                                              | SUCCESS
        "admin parameter modify --name apgPolicyFlowControlConfig --value {FLOW_CONTROL_PERIOD:20,//APG_MED/SyncApgLargeNodeFlow/1.0.0:4}"     | SUCCESS
        "admin parameter modify --name apgPolicyFlowControlConfig --value {FLOW_CONTROL_PERIOD:20}"                                            | SUCCESS
        "admin parameter modify --name abandonTimeOutForAsyncThread --value 500"                                                               | SUCCESS
        "admin parameter modify --name abandonTimeOutForAsyncThread --value 9999"                                                              | SUCCESS
        "admin parameter modify --name additionalFMMediationServiceTypesDeployed --value false"                                                | SUCCESS
        "admin parameter modify --name additionalFMMediationServiceTypesDeployed --value true"                                                 | SUCCESS
        "admin parameter modify --name aiAccount --value abc"                                                                                  | SUCCESS
        "admin parameter modify --name aiAccount --value mm-ai"                                                                                | SUCCESS
    }

    def 'Modify command for SNMP params with invalid parameter value,  response with error returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        parametersValidationFactory.validateSnmpData(_) >> ValidationResult.fail("")
        parametersValidationFactory.validateAuditTime(_) >> ValidationResult.fail("")

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode

        where:
        fullCommand                                                                                                | returnCode              | errorCode
        "admin parameter modify --name NODE_SNMP_SECURITY --value {auth_priv,ABC,password,SHA,password,user}"      | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {auth_priv,123,password,456,password,user}" | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name NODE_SNMP_SECURITY --value {auth,MD5,password,DES,password,user}"           | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {}"                                         | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name AP_SNMP_AUDIT_TIME --value abcd"                                            | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
    }

    def 'Modify command for non-SNMP params with invalid parameter value,  response with error returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        parametersValidationFactory.validateData(_) >> ValidationResult.fail("")

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode

        where:
        fullCommand                                                                                 | returnCode              | errorCode
        "admin parameter modify --name pmicSupportedRopPeriods --value [\"abc,def\"]"               | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name abandonTimeOutForAsyncThread --value {1.23}"                 | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name pmicSupportedRopPeriods --value {}"                          | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name additionalFMMediationServiceTypesDeployed --value '\"abc\"'" | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name aiAccount --value {abc:}"                                    | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
        "admin parameter modify --name aiAccount --value {abc}"                                     | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
    }

    def 'modify command update parameter failure,  response with PARAMETER_VALUE_INVALID_ERROR_CODE returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        errorHandler.getMetaClass() >> String.class

        passwordHelper.encryptEncode(_) >> "encryptedPassword"
        parametersValidationFactory.validateSnmpData(_) >> ValidationResult.fail("")
        configurationService.updateParameter(_) >> false

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode


        where:
        paramName                 | fullCommand                                                                                                | returnCode              | errorCode
        "NODE_SNMP_INIT_SECURITY" | "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {auth_priv,MD5,password,DES,password,user}" | COMMAND_EXECUTION_ERROR | PARAMETER_VALUE_INVALID_ERROR_CODE
    }

    def 'modify command update parameter failure,  response with PARAMETER_UPDATE_FAILURE_ERROR_CODE returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);
        extendedCommandParser.getClass() >> String.class
        errorHandler.getMetaClass() >> String.class

        passwordHelper.encryptEncode(_) >> "encryptedPassword"
        parametersValidationFactory.validateSnmpData(_) >> ValidationResult.ok("")
        configurationService.updateParameter(_) >> false

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode


        where:
        paramName                 | fullCommand                                                                                                                                                                                            | returnCode              | errorCode
        "NODE_SNMP_INIT_SECURITY" | "admin parameter modify --name NODE_SNMP_INIT_SECURITY --value {securityLevel:NO_AUTH_NO_PRIV,authProtocol:NONE,authPassword:Password123,privProtocol:NONE,privPassword:Password456,user:defaultuser}" | COMMAND_EXECUTION_ERROR | PARAMETER_UPDATE_FAILURE_ERROR_CODE
    }

    def 'inValid Modify command for SNMP params,  response with SYNTAX_ERROR_CODE returned '() {

        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode

        where:
        fullCommand                                                                                    | returnCode           | errorCode
        "admin parameter modify --name "                                                               | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
        "admin parameter modify --name NODE_SNMP_INIT_SECURITY --name NODE_SNMP_SECURITY "             | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
        "admin parameter modify --name NODE_SNMP_SECURITY --value "                                    | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
        "admin parameter modify NODE_SNMP_INIT_SECURITY --value {auth_priv,ABC,password,SHA,password}" | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
    }

    def 'inValid Modify command for non-SNMP params,  response with SYNTAX_ERROR_CODE returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);

        when:
        CommandResponseDto response = modifyCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode

        where:
        fullCommand                                                                                                      | returnCode           | errorCode
        "admin parameter modify --name abandonTimeOutForAsyncThread --name abandonTimeOutForAsyncThread "                | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
        "admin parameter modify --name pmicSupportedRopPeriods --value "                                                 | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
        "admin parameter modify additionalFMMediationServiceTypesDeployed --value {auth_priv,ABC,password,SHA,password}" | COMMAND_SYNTAX_ERROR | SYNTAX_ERROR_CODE
    }
}
