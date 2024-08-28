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
package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest;

import static org.mockserver.model.Header.header;
import static org.mockserver.model.Parameter.param;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.entity.ContentType;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import com.ericsson.oss.services.cm.admin.rest.client.common.HttpConstants;

public class NodePluginAndConfigurationMockServer extends ClientAndServer {

    public NodePluginAndConfigurationMockServer(final Integer... port) {
        super(port);
    }

    public void createExpectation(final Expectation expectation) {
        this.when(expectation.request).respond(expectation.response);
    }

    public enum Expectation {
        MODIFY_PARAM_AP_SNMP_AUDIT_TIME_SUCC(Requests.MODIFY_PARAM_AP_SNMP_AUDIT_TIME, Responses.MODIFY_PARAM_AUDIT_TIME_SUCC),
        GET_AP_SNMP_AUDIT_TIME_SUCC(Requests.GET_AP_SNMP_AUDIT_TIME_SUCC, Responses.GET_AP_SNMP_AUDIT_TIME_SUCC),
        GET_NODE_SNMP_INIT_SECURITY_SUCC(Requests.GET_NODE_SNMP_INIT_SECURITY_SUCC, Responses.GET_NODE_SNMP_INIT_SECURITY_SUCC),
        GET_NODE_SNMP_SECURITY_SUCC(Requests.GET_NODE_SNMP_SECURITY_SUCC, Responses.GET_NODE_SNMP_SECURITY_SUCC),
        MODIFY_PARAM_PMIC_SUPPORTED_ROP_PERIODS_SUCC(Requests.MODIFY_PARAM_PMIC_SUPPORTED_ROP_PERIODS, Responses.MODIFY_PARAM_PMIC_SUCC),
        ADMIN_PARAMETER_VIEW_SUCC(Requests.ADMIN_PARAMETER_VIEW_ALL_REQUEST, Responses.ADMIN_PARAMETER_VIEW_ALL_RESPONSE),
        ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_SUCC(Requests.ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_REQUEST, Responses.ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_RESPONSE),
        ADMIN_PARAMETER_VIEW_JVM_SCOPED_SUCC(Requests.ADMIN_PARAMETER_VIEW_JVM_SCOPED_REQUEST, Responses.ADMIN_PARAMETER_VIEW_JVM_SCOPED_RESPONSE),
        ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_SUCC(Requests.ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_REQUEST, Responses.ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_RESPONSE);

        private HttpRequest request;
        private HttpResponse response;

        @SuppressWarnings("unused")
        Expectation(final HttpRequest request, final HttpResponse response) {
            this.request = request;
            this.response = response;
        }

        public HttpRequest getRequest() {
            return request;
        }

    }

    private static final class Requests {
        static final HttpRequest MODIFY_PARAM_AP_SNMP_AUDIT_TIME = HttpRequest.request("/pib/configurationService/updateConfigParameterValue")
                .withQueryStringParameters(param("paramName", "AP_SNMP_AUDIT_TIME"),
                        param("paramValue", "12:30"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));

        static final HttpRequest MODIFY_PARAM_PMIC_SUPPORTED_ROP_PERIODS = HttpRequest.request("/pib/configurationService/updateConfigParameterValue")
                .withQueryStringParameters(param("paramName", "pmicSupportedRopPeriods"),
                        param("paramValue", "ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));

        static final HttpRequest GET_AP_SNMP_AUDIT_TIME_SUCC = HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                .withQueryStringParameters(param("paramName", "AP_SNMP_AUDIT_TIME"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));

        static final HttpRequest GET_NODE_SNMP_INIT_SECURITY_SUCC = HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                .withQueryStringParameters(param("paramName", "NODE_SNMP_INIT_SECURITY"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));

        static final HttpRequest GET_NODE_SNMP_SECURITY_SUCC = HttpRequest.request("/pib/configurationService/getConfigParameterValue")
                .withQueryStringParameters(param("paramName", "NODE_SNMP_SECURITY"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));

        static final HttpRequest ADMIN_PARAMETER_VIEW_ALL_REQUEST = HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));
        static final HttpRequest ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_REQUEST = HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                .withQueryStringParameter(param("serviceIdentifier","ap-workflow-vnf"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));
        static final HttpRequest ADMIN_PARAMETER_VIEW_JVM_SCOPED_REQUEST = HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                .withQueryStringParameter(param("jvmIdentifier","ap-workflow-vnf"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));
        static final HttpRequest ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_REQUEST = HttpRequest.request("/pib/configurationService/getAllConfigParametersInScope")
                .withQueryStringParameter(param("serviceIdentifier","ap-workflow-vnf"))
                .withQueryStringParameter(param("jvmIdentifier","ap-workflow-vnf"))
                .withMethod("GET")
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.ACCEPT_HEADER, ContentType.APPLICATION_JSON.toString()),
                        header(HttpConstants.AUTHORIZATION_HEADER, "Basic " + Base64.encodeBase64String(("pibUser:3ric550N*").getBytes())),
                        header("content-length", "0"),
                        header("User-Agent", "Apache-HttpClient/4.3.6 (java 1.5)"),
                        header("Host", "localhost:1234"),
                        header("Accept-Encoding", "gzip,deflate"));
    }

    private static final class Responses {
        static final HttpResponse MODIFY_PARAM_AUDIT_TIME_SUCC = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()));
        static final HttpResponse MODIFY_PARAM_PMIC_SUCC = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()));
        static final HttpResponse GET_AP_SNMP_AUDIT_TIME_SUCC = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("02:30");
        static final HttpResponse GET_NODE_SNMP_INIT_SECURITY_SUCC = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("[\"securityLevel:NO_AUTH_NO_PRIV\",\"authPassword:\",\"authProtocol:NONE\",\"privPassword:\",\"privProtocol:NONE\",\"user:defaultsnmpuser\"]");
        static final HttpResponse GET_NODE_SNMP_SECURITY_SUCC = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("[\"securityLevel:NO_AUTH_NO_PRIV\",\"authPassword:\",\"authProtocol:NONE\",\"privPassword:\",\"privProtocol:NONE\",\"user:defaultsnmpuser\"]");
        static final HttpResponse ADMIN_PARAMETER_VIEW_ALL_RESPONSE = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("[{\"id\":\"GLOBAL___ALARM_ROUTING_EMAIL_DOMAINS\",\"name\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"jvmIdentifier\":null,\"serviceIdentifier\":null,\"typeAsString\":\"[Ljava.lang.String;\",\"value\":null,\"description\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"overridableInScopes\":[],\"values\":[\"ericsson.com\"],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1651016576141,\"type\":\"[Ljava.lang.String;\",\"scope\":\"GLOBAL\",\"firstNonNullValue\":[\"ericsson.com\"]}]");
        static final HttpResponse ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_RESPONSE = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("[{\"id\":\"GLOBAL___ALARM_ROUTING_EMAIL_DOMAINS\",\"name\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"jvmIdentifier\":null,\"serviceIdentifier\":\"ap-workflow-vnf\",\"typeAsString\":\"[Ljava.lang.String;\",\"value\":null,\"description\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"overridableInScopes\":[],\"values\":[\"ericsson.com\"],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1651016576141,\"type\":\"[Ljava.lang.String;\",\"scope\":\"GLOBAL\",\"firstNonNullValue\":[\"ericsson.com\"]}]");
        static final HttpResponse ADMIN_PARAMETER_VIEW_JVM_SCOPED_RESPONSE = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("[{\"id\":\"GLOBAL___ALARM_ROUTING_EMAIL_DOMAINS\",\"name\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"jvmIdentifier\":\"ap-workflow-vnf\",\"serviceIdentifier\":null,\"typeAsString\":\"[Ljava.lang.String;\",\"value\":null,\"description\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"overridableInScopes\":[],\"values\":[\"ericsson.com\"],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1651016576141,\"type\":\"[Ljava.lang.String;\",\"scope\":\"GLOBAL\",\"firstNonNullValue\":[\"ericsson.com\"]}]");
        static final HttpResponse ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_RESPONSE = HttpResponse.response().withStatusCode(200)
                .withHeaders(header(HttpConstants.CONTENT_TYPE_HEADER, ContentType.APPLICATION_JSON.toString()))
                .withBody("[{\"id\":\"GLOBAL___ALARM_ROUTING_EMAIL_DOMAINS\",\"name\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"jvmIdentifier\":\"ap-workflow-vnf\",\"serviceIdentifier\":\"ap-workflow-vnf\",\"typeAsString\":\"[Ljava.lang.String;\",\"value\":null,\"description\":\"ALARM_ROUTING_EMAIL_DOMAINS\",\"overridableInScopes\":[],\"values\":[\"ericsson.com\"],\"namespace\":\"global\",\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1651016576141,\"type\":\"[Ljava.lang.String;\",\"scope\":\"GLOBAL\",\"firstNonNullValue\":[\"ericsson.com\"]}]");
    }

}
