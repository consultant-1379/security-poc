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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.CredmControllerManager;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringAction;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringStatus;
import com.ericsson.oss.itpf.security.credmservice.http.HttpConnectionFactory;
import com.ericsson.oss.services.security.pkimock.exception.MockCertificateServiceException;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

@SuppressWarnings("restriction")
@RunWith(MockitoJUnitRunner.class)
public class CredmControllerImplTest {
    @Spy
    HttpConnectionFactory httpConnectionFactory = new HttpConnectionFactory();

    @InjectMocks
    CredmControllerManager credmControllerImpl = new CredmControllerImpl();

    private static HttpServer httpServer;

    private static String response = null;
    private static int httpCode = 200;

    @BeforeClass
    public static void startServer()
            throws IOException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException {
        System.setProperty("credmcontroller.host.name", "localhost");
        System.setProperty("credmcontroller.port", "5001");
        // Create the HTTP test server
        httpServer = HttpServer.create(new InetSocketAddress(5001), 0);
        httpServer.createContext("/monitoring", new ServerRequestHandler());
        httpServer.setExecutor(null); // creates a default executor
        httpServer.start();
    }

    @AfterClass
    public static void stopServer() {
        httpServer.stop(0);
    }

    @Test
    public void getMonitoringEnableTest() throws ReflectiveOperationException, IOException {
        response = "{\"status\":\"enabled\"}";
        httpCode = 200;
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.getMonitoring();
        assertTrue(monitoringResponse.getHttpStatus() == 200);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.ENABLED);
    }

    @Test
    public void getMonitoringInternalErrorTest() throws ReflectiveOperationException, IOException {
        response = "";
        httpCode = 500;
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.getMonitoring();
        assertTrue(monitoringResponse.getHttpStatus() == 500);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.EMPTY);
    }

    @Test
    public void getMonitoringNotFoundTest() throws ReflectiveOperationException, IOException {
        response = "";
        httpCode = 404;
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.getMonitoring();
        assertTrue(monitoringResponse.getHttpStatus() == 404);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.EMPTY);
    }

    @Test
    public void getMonitoringWrongHostTest() {
        System.setProperty("credmcontroller.host.name", "localhost1");
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.getMonitoring();

        assertTrue(monitoringResponse.getHttpStatus() == 500);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.EMPTY);
        System.setProperty("credmcontroller.host.name", "localhost");

    }

    @Test
    public void getMonitoringWithoutPropertyTest() {
        System.clearProperty("credmcontroller.host.name");
        System.clearProperty("credmcontroller.port");
        try {
            final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.getMonitoring();
            assertTrue(monitoringResponse.getHttpStatus() == 500);
        } catch (final MockCertificateServiceException ex) {
            assertTrue(true);
        }

        System.setProperty("credmcontroller.host.name", "localhost");
        System.setProperty("credmcontroller.port", "5001");
    }

    @Test
    public void setMonitoringDisableTest() throws ReflectiveOperationException, IOException {
        response = "{\"status\":\"disabled\"}";
        httpCode = 200;
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.setMonitoring(CredentialManagerMonitoringAction.DISABLE);
        assertTrue(monitoringResponse.getHttpStatus() == 200);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.DISABLED);
    }

    @Test
    public void setMonitoringNotFoundTest() throws ReflectiveOperationException, IOException {
        response = "";
        httpCode = 404;
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.setMonitoring(CredentialManagerMonitoringAction.DISABLE);
        assertTrue(monitoringResponse.getHttpStatus() == 404);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.EMPTY);
    }

    @Test
    public void setMonitoringInternalErrorTest() throws ReflectiveOperationException, IOException {
        response = "";
        httpCode = 500;
        final CredentialManagerMonitoringResponse monitoringResponse = credmControllerImpl.setMonitoring(CredentialManagerMonitoringAction.DISABLE);
        assertTrue(monitoringResponse.getHttpStatus() == 500);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.EMPTY);
    }

    static class ServerRequestHandler implements HttpHandler {

        @Override
        public void handle(final com.sun.net.httpserver.HttpExchange t) throws IOException {
            t.sendResponseHeaders(httpCode, response.length());
            final OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

        void setResponse() {

        }
    }
}
