package com.ericsson.oss.services.cm.admin.cli.handler

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationRestServiceException
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationService
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths

import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.PARAMETER_NOT_EXIST_ERROR_CODE
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.SYNTAX_ERROR_CODE
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_EXECUTION_ERROR
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_SYNTAX_ERROR
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.SUCCESS;

import javax.inject.Inject

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.cli.CliCommand
import com.ericsson.oss.services.cm.admin.cli.parser.ExtendedCommandParser
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto

class ViewCommandHandlerSpec extends CdiSpecification {
    @Inject
    private ViewCommandHandler viewCommandHandler;

    @ImplementationInstance
    private ConfigurationService configurationService = Mock(ConfigurationService);

    @Inject
    private ExtendedCommandParser extendedCommandParser = Mock();

    @ImplementationInstance
    private PasswordHelper passwordHelper = Mock(PasswordHelper);

    def 'Valid View command for snmp data, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand)
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "[\"securityLevel:NO_AUTH_NO_PRIV\",\"authPassword:encryptedPassword\",\"authProtocol:NONE\",\"privPassword:encryptedPassword\",\"privProtocol:NONE\",\"user:defaultsnmpuser\"]"
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.responseDto. toString().contains("deencryptedPassword") == true
        response.responseDto. toString().contains("{securityLevel:NO_AUTH_NO_PRIV,authProtocol:NONE,authPassword:deencryptedPassword,privProtocol:NONE,privPassword:deencryptedPassword,user:defaultsnmpuser}") == true

        where:
        fullCommand                                             | returnCode
        "admin parameter view --name NODE_SNMP_INIT_SECURITY"   | SUCCESS
    }

    def 'Valid View command for data containing list of string, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name pmicSupportedRopPeriods");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "[\"ONE_MIN\",\"FIVE_MIN\",\"FIFTEEN_MIN\",\"THIRTY_MIN\",\"ONE_HOUR\",\"TWELVE_HOUR\"]"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
        response.getResponseDto().toString().contains("[ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR]") == true

    }

    def 'Valid View command for data containing list of apgPolicyFlowControlConfig, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name apgPolicyFlowControlConfig");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "[\"FLOW_CONTROL_PERIOD:20\",\"//APG_MED/SyncApgLargeNodeFlow/1.0.0:4\"]"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
        response.getResponseDto().toString().contains("{FLOW_CONTROL_PERIOD:20,//APG_MED/SyncApgLargeNodeFlow/1.0.0:4}") == true

    }

    def 'Valid View command for AP_SNMP_AUDIT_TIME, success response returned'() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name AP_SNMP_AUDIT_TIME");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "03:45"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'Valid View command for AP_SNMP_AUDIT_TIME, Internal Server error occured'() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name AP_SNMP_AUDIT_TIME");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> {throw new ConfigurationRestServiceException("internal error")}

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == COMMAND_EXECUTION_ERROR
    }

    def 'Valid view all global scoped parameters, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view");
        extendedCommandParser.getClass() >> String.class
        TypeReference<List<ConfigurationParameter>> typeReference = new TypeReference<List<ConfigurationParameter>>() {};
        String pibGetAllData = "[{\"id\":\"GLOBAL___abandonTimeOutForAsyncThread\",\"name\":\"abandonTimeOutForAsyncThread\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Integer\",\"value\":\"600\",\"description\":\"Abandon timeout (in sec) for async threads in CM reader service\",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648792606408,\"scope\":\"GLOBAL\",\"type\":\"java.lang.Integer\",\"firstNonNullValue\":\"600\"},{\"id\":\"GLOBAL___additionalFMMediationServiceTypesDeployed\",\"name\":\"additionalFMMediationServiceTypesDeployed\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Boolean\",\"value\":\"false\",\"description\":\"Parameter for knowing if additional FM mediaiton service types are deployed in system.\",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648772291486,\"scope\":\"GLOBAL\",\"type\":\"java.lang.Boolean\",\"firstNonNullValue\":\"false\"}]"
        ObjectMapper objectMapper = new ObjectMapper();
        List<ConfigurationParameter> parameterList = (List<ConfigurationParameter>) objectMapper.readValue(pibGetAllData, typeReference)
        configurationService.getAllParameter(_) >> parameterList
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
        response.getResponseDto().toString().contains("abandonTimeOutForAsyncThread") == true
        response.getResponseDto().toString().contains("additionalFMMediationServiceTypesDeployed") == true
    }

    def 'Valid admin parameter view all global scoped parameters command, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view");
        extendedCommandParser.getClass() >> String.class
        TypeReference<List<ConfigurationParameter>> typeReference = new TypeReference<List<ConfigurationParameter>>() {};
        def path = Paths.get("src/test/resources/PibGlobalParams");
        def buffer = Files.readAllBytes(path);
        def pibGetAllData = new String(buffer, StandardCharsets.UTF_8);
        ObjectMapper objectMapper = new ObjectMapper();
        List<ConfigurationParameter> parameterList = (List<ConfigurationParameter>) objectMapper.readValue(pibGetAllData, typeReference)
        configurationService.getAllParameter(_) >> parameterList
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS

    }

    def 'Valid admin parameter view service identifier command, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --service_identifier ap-workflow-vnf --all");
        extendedCommandParser.getClass() >> String.class
        TypeReference<List<ConfigurationParameter>> typeReference = new TypeReference<List<ConfigurationParameter>>() {};
        def path = Paths.get("src/test/resources/PibServiceIdentifierParams");
        def buffer = Files.readAllBytes(path);
        def pibGetAllData = new String(buffer, StandardCharsets.UTF_8);
        ObjectMapper objectMapper = new ObjectMapper();
        List<ConfigurationParameter> parameterList = (List<ConfigurationParameter>) objectMapper.readValue(pibGetAllData, typeReference)
        configurationService.getAllParameter(_) >> parameterList
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'Valid admin parameter view command along with name and service identifier keyword, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name jndiBind --service_identifier mediationservice");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient"
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'Valid admin parameter view command along with name and jvm identifier keyword, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name jndiBind --app_server_identifier mediationservice");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient"
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'Valid admin parameter view command along with name, service and jvm identifier keyword, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name jndiBind --service_identifier mediationservice --app_server_identifier mediationservice");
        extendedCommandParser.getClass() >> String.class
        configurationService.getParameter(_) >> "mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient"
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'Valid admin parameter view jvm identifier command, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --app_server_identifier ap-workflow-vnf --all");
        extendedCommandParser.getClass() >> String.class
        TypeReference<List<ConfigurationParameter>> typeReference = new TypeReference<List<ConfigurationParameter>>() {};
        def path = Paths.get("src/test/resources/PibJvmIdentifierParams");
        def buffer = Files.readAllBytes(path);
        def pibGetAllData = new String(buffer, StandardCharsets.UTF_8);
        ObjectMapper objectMapper = new ObjectMapper();
        List<ConfigurationParameter> parameterList = (List<ConfigurationParameter>) objectMapper.readValue(pibGetAllData, typeReference)
        configurationService.getAllParameter(_) >> parameterList
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'Valid admin parameter view service and jvm identifier command, success response returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --service_identifier mediationservice --app_server_identifier svc-5-mscmip --all");
        extendedCommandParser.getClass() >> String.class
        TypeReference<List<ConfigurationParameter>> typeReference = new TypeReference<List<ConfigurationParameter>>() {};
        def path = Paths.get("src/test/resources/PibServiceAndJvmIdentifierParams");
        def buffer = Files.readAllBytes(path);
        def pibGetAllData = new String(buffer, StandardCharsets.UTF_8);
        ObjectMapper objectMapper = new ObjectMapper();
        List<ConfigurationParameter> parameterList = (List<ConfigurationParameter>) objectMapper.readValue(pibGetAllData, typeReference)
        configurationService.getAllParameter(_) >> parameterList
        passwordHelper.decryptDecode(_) >> "deencryptedPassword"

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == SUCCESS
    }

    def 'view command with inValid parameter name,  response with PARAMETER_NOT_EXIST_ERROR_CODE returned '() {
        given:
        final CliCommand cliCommand = new CliCommand("admin parameter view --name t");

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == COMMAND_EXECUTION_ERROR
        response.getErrorCode() == PARAMETER_NOT_EXIST_ERROR_CODE
    }

    def 'inValid View command,  response with SYNTAX_ERROR_CODE returned '() {
        given:
        final CliCommand cliCommand = new CliCommand(fullCommand);

        when:
        CommandResponseDto response = viewCommandHandler.processCommand(cliCommand)

        then:
        response.getStatusCode() == returnCode
        response.getErrorCode() == errorCode

        where:
        fullCommand                                                                 | returnCode                | errorCode
        "admin parameter view --name "                                              |  COMMAND_SYNTAX_ERROR     | SYNTAX_ERROR_CODE
        "admin parameter view --name NODE_SNMP_SECURITY --name NODE_SNMP_SECURITY " |  COMMAND_SYNTAX_ERROR     | SYNTAX_ERROR_CODE
        "admin parameter view --test NODE_SNMP_SECURITY "                           |  COMMAND_SYNTAX_ERROR     | SYNTAX_ERROR_CODE
        "admin parameter view NODE_SNMP_SECURITY"                                   |  COMMAND_SYNTAX_ERROR     | SYNTAX_ERROR_CODE
    }
}
