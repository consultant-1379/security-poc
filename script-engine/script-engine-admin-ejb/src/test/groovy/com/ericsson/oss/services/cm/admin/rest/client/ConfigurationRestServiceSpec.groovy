package com.ericsson.oss.services.cm.admin.rest.client

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationParameterFilterCriteria
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationRestServiceException
import com.ericsson.oss.services.cm.admin.utility.ConfigurationServiceHelper

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths

import static org.mockserver.model.HttpResponse.response
import static org.mockserver.model.Parameter.param;

import javax.inject.Inject

import org.apache.commons.codec.binary.Base64
import org.apache.http.entity.ContentType
import org.mockserver.integration.ClientAndServer
import org.mockserver.model.Header
import org.mockserver.model.HttpRequest
import org.mockserver.model.HttpStatusCode

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.rest.client.common.HttpConstants
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationRestService
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper

class ConfigurationRestServiceSpec extends CdiSpecification {

    @ImplementationInstance
    private PasswordHelper passwordHelper = Mock();

    @Inject
    private ConfigurationRestService configurationService;

    @Inject
    private ConfigurationServiceHelper configurationServiceHelper;

    private static final String INTERNAL_URL = "INTERNAL_URL"
    private static ClientAndServer mockServerClient
    private final static String USERNAME = "pibUser";
    private final static String PASSWORD = "3ric550N*";

    def setupSpec() {
        System.setProperty(INTERNAL_URL, "http://localhost:8080")
        mockServerClient = ClientAndServer.startClientAndServer(8080)
    }

    def cleanupSpec() {
        mockServerClient.stop()
    }

    def setup() {
        mockServerClient.reset()
    }

    def "Configuration service should return proper response when updating global scoped configuration parameter"() {

        def parmName = "NODE_SNMP_INIT_SECURITY"
        def parmValue = "securityLevel:AUTH_PRIV,authPassword:onlytset,authProtocol:MD5,privPassword:onlytest,privProtocol:AES128,user:defaultuser"
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setName(parmName)
        configurationParameter.setValue(parmValue)

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/updateConfigParameterValue")
                .withQueryStringParameters(param("paramName",parmName),param("paramValue",parmValue))
                .withMethod("GET")
                .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                .withHeader(Header.header("Connection", "Keep-Alive"))
                .withHeader(Header.header("content-length", "0"))
                .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                .withHeader(Header.header("Host", "localhost:8080"))
                .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                .withStatusCode(HttpStatusCode.OK_200.code())
                .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                )

        when:

        def result = configurationService.updateParameter(configurationParameter)

        then:
        result
    }

    def "Configuration service should return proper response when updating service scoped configuration parameter"() {

        def parmName = "jndiBind"
        def parmValue = "mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient"
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setServiceIdentifier("mediationservice")
        configurationParameter.setName(parmName)
        configurationParameter.setValue(parmValue)

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/updateConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName),param("paramValue",parmValue))
                        .withQueryStringParameter("serviceIdentifier", configurationParameter.getServiceIdentifier())
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient")
                )

        when:

        def result = configurationService.updateParameter(configurationParameter)

        then:
        result == true
    }

    def "Configuration service should return proper response when updating jvm scoped configuration parameter"() {

        def parmName = "jndiBind"
        def parmValue = "mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient"
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setJvmIdentifier("mediationservice")
        configurationParameter.setName(parmName)
        configurationParameter.setValue(parmValue)

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/updateConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName),param("paramValue",parmValue))
                        .withQueryStringParameter("jvmIdentifier", configurationParameter.getJvmIdentifier())
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient")
                )

        when:

        def result = configurationService.updateParameter(configurationParameter)

        then:
        result == true
    }

    def "Configuration service should return proper response when updating both service and jvm scoped configuration parameter"() {

        def parmName = "jndiBind"
        def parmValue = "mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient"
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setJvmIdentifier("mediationservice")
        configurationParameter.setServiceIdentifier("mediationservice")
        configurationParameter.setName(parmName)
        configurationParameter.setValue(parmValue)

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/updateConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName),param("paramValue",parmValue))
                        .withQueryStringParameter("serviceIdentifier", configurationParameter.getServiceIdentifier())
                        .withQueryStringParameter("jvmIdentifier", configurationParameter.getJvmIdentifier())
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("mediation-service-mssnmpfm-6d79bc5797-d8hxv/mediation-engine-ejb/MediationServiceClientBean!com.ericsson.oss.mediation.service.MediationServiceClient")
                )

        when:

        def result = configurationService.updateParameter(configurationParameter)

        then:
        result == true
    }

    def "Configuration service should send proper GET request when reading configuration"() {

        def parmName = "AP_SNMP_AUDIT_TIME"

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setName("AP_SNMP_AUDIT_TIME")
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("02:45")
                )

        when:

        def result = configurationService.getParameter(configurationParameterFilterCriteria)

        then:
        result
    }

    def "Configuration service should return proper response when viewing specific service scoped parameter"() {

        def parmName = "wfs_upgrade_timeout_interval_min"

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setName(parmName)
        configurationParameter.setServiceIdentifier("shm-cli")
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName))
                        .withQueryStringParameters(param("serviceIdentifier",configurationParameter.getServiceIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("50")
                )

        when:

        def result = configurationService.getParameter(configurationParameterFilterCriteria)

        then:
        result == "50"
    }

    def "Configuration service should return proper response when viewing specific jvm scoped parameter"() {

        def parmName = "wfs_upgrade_timeout_interval_min"

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setName(parmName)
        configurationParameter.setJvmIdentifier("shm-cli")
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName))
                        .withQueryStringParameters(param("jvmIdentifier",configurationParameter.getJvmIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("50")
                )

        when:

        def result = configurationService.getParameter(configurationParameterFilterCriteria)

        then:
        result == "50"
    }

    def "Configuration service should return proper response when viewing specific service and jvm scoped parameter"() {

        def parmName = "wfs_upgrade_timeout_interval_min"

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        ConfigurationParameter configurationParameter = new ConfigurationParameter()
        configurationParameter.setName(parmName)
        configurationParameter.setServiceIdentifier("shm-cli")
        configurationParameter.setJvmIdentifier("shm-cli")
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                        .withQueryStringParameters(param("paramName",parmName))
                        .withQueryStringParameters(param("jvmIdentifier",configurationParameter.getJvmIdentifier()))
                        .withQueryStringParameters(param("serviceIdentifier",configurationParameter.getServiceIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("50")
                )

        when:

        def result = configurationService.getParameter(configurationParameterFilterCriteria)

        then:
        result == "50"
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as boolean"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___writerExtraLogging\",\"name\":\"writerExtraLogging\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Boolean\",\"value\":\"false\",\"description\":\"Enable extra logging for Writer Commands \",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1650907413187,\"type\":\"java.lang.Boolean\",\"scope\":\"GLOBAL\",\"firstNonNullValue\":\"false\"}]")
                )

        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as list"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___ALARM_ROUTING_EMAIL_DOMAINS\",\"name\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"[Ljava.lang.String;\",\"value\":null,\"description\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"overridableInScopes\":[],\"values\":[\"ericsson.com\"],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1651016576141,\"type\":\"[Ljava.lang.String;\",\"scope\":\"GLOBAL\",\"firstNonNullValue\":[\"ericsson.com\"]}]\n")
                )

        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as integer"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___abandonTimeOutForAsyncThread\",\"name\":\"abandonTimeOutForAsyncThread\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Integer\",\"value\":\"600\",\"description\":\"Abandon timeout (in sec) for async threads in CM reader service\",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648792606408,\"scope\":\"GLOBAL\",\"type\":\"java.lang.Integer\",\"firstNonNullValue\":\"600\"}]"))

        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as long"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___activationDelayInterval\",\"name\":\"activationDelayInterval\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Long\",\"value\":\"2\",\"description\":\"Activation delay Time in Minutes  which get used when pmFunction ON\",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648776947381,\"scope\":\"GLOBAL\",\"type\":\"java.lang.Long\",\"firstNonNullValue\":\"2\"}]"))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as string"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___aiAccountPrefix\",\"name\":\"aiAccountPrefix\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.String\",\"value\":\"mm-ai-\",\"description\":\"Account Prefix\",\"overridableInScopes\":[\"SERVICE\"],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648801853770,\"scope\":\"GLOBAL\",\"type\":\"java.lang.String\",\"firstNonNullValue\":\"mm-ai-\"}]"))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as double"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___cmEventsResourceRetryExponentialBackoff\",\"name\":\"cmEventsResourceRetryExponentialBackoff\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Double\",\"value\":\"2.0\",\"description\":\"Exponential backoff to be applied over the wait time between each attempt of getting the resource location.\",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648773721416,\"scope\":\"GLOBAL\",\"type\":\"java.lang.Double\",\"firstNonNullValue\":\"2.0\"}]"))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading global parameter list with parameter value type as object"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"id\":\"GLOBAL___NODE_SNMP_INIT_SECURITY\",\"name\":\"NODE_SNMP_INIT_SECURITY\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"[Ljava.lang.String;\",\"value\":null,\"description\":\"SNMP parameter setting for nodeup\",\"overridableInScopes\":[],\"values\":[\"securityLevel:NO_AUTH_NO_PRIV\",\"authPassword:\",\"authProtocol:NONE\",\"privPassword:\",\"privProtocol:NONE\",\"user:defaultsnmpuser\"],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648792602859,\"scope\":\"GLOBAL\",\"type\":\"[Ljava.lang.String;\",\"firstNonNullValue\":[\"securityLevel:NO_AUTH_NO_PRIV\",\"authPassword:\",\"authProtocol:NONE\",\"privPassword:\",\"privProtocol:NONE\",\"user:defaultsnmpuser\"]}]"))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
        result.get(0).class == ConfigurationParameter
    }

    def "Configuration service should send proper GET request when reading all global parameters"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def path = Paths.get("src/test/resources/PibGlobalParams")
        def buffer = Files.readAllBytes(path)
        def content = new String(buffer, StandardCharsets.UTF_8)
        def configurationParameter = new ConfigurationParameter()
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody(content))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1186
    }

    def "Configuration service should send proper GET request when reading all service scoped parameters"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def path = Paths.get("src/test/resources/PibServiceIdentifierParams")
        def buffer = Files.readAllBytes(path)
        def content = new String(buffer, StandardCharsets.UTF_8)
        def configurationParameter = new ConfigurationParameter()
        configurationParameter.setServiceIdentifier("ap-workflow-vnf")
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withQueryStringParameter(param("serviceIdentifier",configurationParameter.getServiceIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody(content))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 2
    }

    def "Configuration service should send proper GET request when reading all jvm scoped parameters"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def path = Paths.get("src/test/resources/PibJvmIdentifierSingleParamList")
        def buffer = Files.readAllBytes(path)
        def content = new String(buffer, StandardCharsets.UTF_8)
        def configurationParameter = new ConfigurationParameter()
        configurationParameter.setJvmIdentifier("svc-5-mscmip")
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withQueryStringParameter(param("jvmIdentifier",configurationParameter.getJvmIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody(content))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
    }

    def "Configuration service should send proper GET request when reading all jvm and service scoped parameters"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def path = Paths.get("src/test/resources/PibServiceAndJvmIdentifierSingleParamList")
        def buffer = Files.readAllBytes(path)
        def content = new String(buffer, StandardCharsets.UTF_8)
        def configurationParameter = new ConfigurationParameter()
        configurationParameter.setJvmIdentifier("svc-5-mscmip")
        configurationParameter.setServiceIdentifier("mediationservice")
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withQueryStringParameter(param("serviceIdentifier",configurationParameter.getServiceIdentifier()))
                        .withQueryStringParameter(param("jvmIdentifier",configurationParameter.getJvmIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody(content))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result != null
        result.size() == 1
    }

    def "Configuration service should throw exception when api returns internal server error"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        configurationParameter.setServiceIdentifier("ap-workflow-vnf")
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withQueryStringParameter(param("serviceIdentifier",configurationParameter.getServiceIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.INTERNAL_SERVER_ERROR_500.code()))
        when:

        configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        ConfigurationRestServiceException exception = thrown()
    }

    def "Empty list should be returned when response data from api is not in proper format"() {

        given:
        passwordHelper.decryptDecode(_) >>> [USERNAME, PASSWORD]
        def configurationParameter = new ConfigurationParameter()
        configurationParameter.setServiceIdentifier("ap-workflow-vnf")
        def configurationParameterFilterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter)

        mockServerClient
                .when(HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                        .withQueryStringParameter(param("serviceIdentifier",configurationParameter.getServiceIdentifier()))
                        .withMethod("GET")
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withHeader(Header.header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String((USERNAME + ":" + PASSWORD).getBytes())))
                        .withHeader(Header.header("Connection", "Keep-Alive"))
                        .withHeader(Header.header("content-length", "0"))
                        .withHeader(Header.header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"))
                        .withHeader(Header.header("Host", "localhost:8080"))
                        .withHeader(Header.header("Accept-Encoding", "gzip,deflate"))
                )
                .respond(response()
                        .withStatusCode(HttpStatusCode.OK_200.code())
                        .withHeader(Header.header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                        .withBody("[{\"di\":\"GLOBAL___abandonTimeOutForAsyncThread\",\"anme\":\"abandonTimeOutForAsyncThread\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"java.lang.Integer\",\"value\":\"600\",\"description\":\"Abandon timeout (in sec) for async threads in CM reader service\",\"overridableInScopes\":[],\"values\":[],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1648792606408,\"scope\":\"GLOBAL\",\"type\":\"java.lang.Integer\",\"firstNonNullValue\":\"600\"}]"))
        when:

        def result = configurationService.getAllParameter(configurationParameterFilterCriteria)

        then:
        result.size() == 0
    }
}

