/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.core.MediaType;

import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.api.CredmControllerManager;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringAction;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringStatus;
import com.ericsson.oss.itpf.security.credmservice.http.HttpClientUtility;
import com.ericsson.oss.itpf.security.credmservice.http.HttpConnectionFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CredmControllerImpl implements CredmControllerManager {

    private static final String ERIC_ENM_CREDM_CONTROLLER = "eric-enm-credm-controller";
    private static final int CREDMCONTROLLER_PORT = 5001;

    private static final Logger log = LoggerFactory.getLogger(CredmControllerImpl.class);

    @Inject
    HttpConnectionFactory httpConnectionFactory;

    @Override
    public CredentialManagerMonitoringResponse getMonitoring() {
        CloseableHttpResponse response = null;
        final HttpHost httpHost = new HttpHost(getCredmControllerHost(), getCredmControllerPort(), "http");
        final List<NameValuePair> headers = new ArrayList<>();
        headers.add(new BasicNameValuePair("Content-Type", MediaType.APPLICATION_JSON));

        final HttpGet get = HttpClientUtility.generateGet(httpHost, "/monitoring", headers);
        CredentialManagerMonitoringResponse monitoringResponse = null;
        try {
            response = HttpClientUtility.executeQuery(get, httpConnectionFactory.getClient());
            final int responseCode = response.getStatusLine().getStatusCode();
            if (responseCode == HttpStatus.SC_OK) {
                final String jsonResponse = EntityUtils.toString(response.getEntity());
                final ObjectMapper mapper = new ObjectMapper();
                mapper.configure(JsonParser.Feature.ALLOW_SINGLE_QUOTES, true);
                final GetMonitoringResponse monitoringRespObj = mapper.readValue(jsonResponse, GetMonitoringResponse.class);
                monitoringResponse = new CredentialManagerMonitoringResponse(HttpStatus.SC_OK, CredentialManagerMonitoringStatus.fromString(monitoringRespObj.getStatus()));
            } else {
                monitoringResponse = new CredentialManagerMonitoringResponse(responseCode, CredentialManagerMonitoringStatus.EMPTY);
            }
            EntityUtils.consume(response.getEntity());
        } catch (final IOException e) {
            log.error("Error in getMonitoring executeGetQuery ", e);
            monitoringResponse = new CredentialManagerMonitoringResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, CredentialManagerMonitoringStatus.EMPTY);
        }
        return monitoringResponse;

    }

    @Override
    public CredentialManagerMonitoringResponse setMonitoring(final CredentialManagerMonitoringAction monitoringAction) {
        CloseableHttpResponse response = null;
        final HttpHost httpHost = new HttpHost(getCredmControllerHost(), getCredmControllerPort(), "http");
        final List<NameValuePair> headers = new ArrayList<>();
        headers.add(new BasicNameValuePair("Content-Type", MediaType.APPLICATION_JSON));
        final String monitoringStatusStr = monitoringAction.getText();
        final StringBuilder uri = new StringBuilder("/monitoring?action=");
        uri.append(monitoringStatusStr);
        final HttpPut put = HttpClientUtility.generatePut(httpHost, uri.toString(), headers, null);
        CredentialManagerMonitoringResponse monitoringResponse = null;
        try {
            response = HttpClientUtility.executeQuery(put, httpConnectionFactory.getClient());
            if (response != null) {
                final int responseCode = response.getStatusLine().getStatusCode();
                if (response.getEntity() != null && responseCode != HttpStatus.SC_NOT_FOUND) {
                    final String jsonResponse = EntityUtils.toString(response.getEntity());
                    final ObjectMapper mapper = new ObjectMapper();
                    mapper.configure(JsonParser.Feature.ALLOW_SINGLE_QUOTES, true);

                    final GetMonitoringResponse monitoringRespObj = mapper.readValue(jsonResponse, GetMonitoringResponse.class);
                    monitoringResponse = new CredentialManagerMonitoringResponse(responseCode, CredentialManagerMonitoringStatus.fromString(monitoringRespObj.getStatus()));
                } else {
                    monitoringResponse = new CredentialManagerMonitoringResponse(responseCode, CredentialManagerMonitoringStatus.EMPTY);
                }
                EntityUtils.consume(response.getEntity());
            }
        } catch (final IOException e) {
            log.error("Error in getMonitoring executePutQuery ", e);
            monitoringResponse = new CredentialManagerMonitoringResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, CredentialManagerMonitoringStatus.EMPTY);
        }
        return monitoringResponse;
    }

    public String getCredmControllerHost() {
        final String prop = System.getProperty("credmcontroller.host.name");
        if (prop != null) {
            return prop;
        }
        final String hostName = System.getenv("CREDM_CONTROLLER_NAME");
        if (hostName != null) {
            return hostName;
        }
        return ERIC_ENM_CREDM_CONTROLLER;
    }

    private int getCredmControllerPort() {
        final String prop = System.getProperty("credmcontroller.port");
        if (prop != null) {
            return Integer.valueOf(prop);
        }
        final String port = System.getenv("CREDM_CONTROLLER_PORT");
        if (port != null) {
            return Integer.valueOf(port);
        }
        return CREDMCONTROLLER_PORT;
    }
}
