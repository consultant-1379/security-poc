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
package com.ericsson.oss.itpf.security.credmservice.http;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.util.EntityUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

@SuppressWarnings("restriction")
public class HttpClientUtilityTest {

    private static final String GOT_IT = "got it!";
    private static HttpServer httpServer;

    private final HttpConnectionFactory httpConnectionFactory;

    public HttpClientUtilityTest() {
        httpConnectionFactory = new HttpConnectionFactory();
        httpConnectionFactory.init();
    }

    @BeforeClass
    public static void startServer()
            throws IOException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException {

        //Create the HTTP test server
        httpServer = HttpServer.create(new InetSocketAddress(12000), 0);
        httpServer.createContext("/test", new ServerRequestHandler());
        httpServer.setExecutor(null); // creates a default executor
        httpServer.start();
    }

    @AfterClass
    public static void stopServer() {
        httpServer.stop(0);
    }

    @Test
    public void httpGetTest() throws IOException {
        final HttpHost httpHost = new HttpHost("localhost", 12000, "http");
        final List<NameValuePair> headers = new ArrayList<>();
        final HttpGet get = HttpClientUtility.generateGet(httpHost, "/test", headers);
        final CloseableHttpResponse result = HttpClientUtility.executeQuery(get, httpConnectionFactory.getClient());
        assertTrue(GOT_IT.equals(EntityUtils.toString(result.getEntity())));
    }

    @Test
    public void httpGetErrorTest() throws IOException {
        final HttpHost httpHost = new HttpHost("localhost", 12000, "http");
        final List<NameValuePair> headers = new ArrayList<>();
        final HttpGet get = HttpClientUtility.generateGet(httpHost, "/notest", headers);
        final CloseableHttpResponse response = HttpClientUtility.executeQuery(get, httpConnectionFactory.getClient());
        final int responseCode = response.getStatusLine().getStatusCode();
        if (responseCode == 200) {
            fail("Unexpected response");
        }
    }

    @Test
    public void httpPutTest() throws IOException {
        final HttpHost httpHost = new HttpHost("localhost", 12000, "http");
        final List<NameValuePair> headers = new ArrayList<>();
        final HttpPut put = HttpClientUtility.generatePut(httpHost, "/test", headers, "");
        final CloseableHttpResponse result = HttpClientUtility.executeQuery(put, httpConnectionFactory.getClient());
        assertTrue(GOT_IT.equals(EntityUtils.toString(result.getEntity())));
    }

    @Test
    public void httpPutErrorTest() throws IOException {
        final HttpHost httpHost = new HttpHost("localhost", 12000, "http");
        final List<NameValuePair> headers = new ArrayList<>();
        final HttpPut put = HttpClientUtility.generatePut(httpHost, "/notest", headers, "");
        final CloseableHttpResponse response = HttpClientUtility.executeQuery(put, httpConnectionFactory.getClient());
        final int responseCode = response.getStatusLine().getStatusCode();
        if (responseCode == 200) {
            fail("Unexpected response");
        }
    }

    static class ServerRequestHandler implements HttpHandler {

        @Override
        public void handle(final HttpExchange t) throws IOException {
            final String response = GOT_IT;
            t.sendResponseHeaders(200, response.length());
            final OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
