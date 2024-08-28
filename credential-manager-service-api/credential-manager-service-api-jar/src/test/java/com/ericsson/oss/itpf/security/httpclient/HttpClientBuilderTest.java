package com.ericsson.oss.itpf.security.httpclient;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.CertificateWriter;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.business.CertificateManager;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Created by enmadmin on 4/3/15.
 */
public class HttpClientBuilderTest {

    private static final Logger LOG = LogManager.getLogger(HttpClientBuilderTest.class);
    
    private static HttpServer server;
    private static int port;

    /**
     * Returns a free port number on localhost.
     * 
     * Heavily inspired from org.eclipse.jdt.launching.SocketUtil (to avoid a dependency to JDT just because of this). Slightly improved with close() missing in JDT. And throws exception instead of
     * returning -1.
     * 
     * @return a free port number on localhost
     * @throws IllegalStateException
     *             if unable to find a free port
     */
    private static int findFreePort() {
        ServerSocket socket = null;
        try {
            socket = new ServerSocket(0);
            socket.setReuseAddress(true);
            final int port = socket.getLocalPort();
            try {
                socket.close();
            } catch (final IOException e) {
                // Ignore IOException on close()
            }
            LOG.info("found free port number: " + port);
            return port;
        } catch (final IOException e) {
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (final IOException e) {
                }
            }
        }
        throw new IllegalStateException("Could not find a free TCP/IP port to start embedded Jetty HTTP Server on");
    }

    @BeforeClass
    public static void initHttpServer() throws Exception {
        port = findFreePort();
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/test", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    public static void shutdownHttpServer() throws Exception {
        server.stop(0);
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            final String response = "hello";
            t.sendResponseHeaders(200, response.length());
            final OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    @Test
    public void testBuildHttpClient() throws IOException {
        final CloseableHttpClient closeableHttpClient = new HttpClientBuilder().buildHttpClient();
        Assert.assertTrue(closeableHttpClient != null);

        final HttpHost localhost = new HttpHost("localhost", port);
        final HttpGet httpGet = new HttpGet("/test");
        final CloseableHttpResponse execute = closeableHttpClient.execute(localhost, httpGet);
        final String toString = EntityUtils.toString(execute.getEntity());
        Assert.assertEquals("hello", toString);

    }

    @Test
    public void testBuildHttpsClient() {

        final String keyStoreFile = "/tmp/boss02.jks";
        final File file = new File(keyStoreFile);

        CertificateWriter.writeKeyAndCertificate(new CertificateManager(null), CertificateFormat.JKS, keyStoreFile, CertificateWriter.CertMode.valid);

        try {
            final CloseableHttpClient closeableHttpClient = new HttpClientBuilder().buildHttpsClient().setAllowedProtocols("TLSv1").addKeystore(file, "keyStorePwd")
                    .addTrustore(file, "keyStorePwd", true).build();
            Assert.assertNotNull(closeableHttpClient);
        } catch (final Exception e) {
            Assert.assertTrue(false);
        }
        file.delete();
    }
    
    @Test
    public void testBuildHttpsClientDefaultProtocols() {

        final String keyStoreFile = "/tmp/boss03.jks";
        final File file = new File(keyStoreFile);

        CertificateWriter.writeKeyAndCertificate(new CertificateManager(null), CertificateFormat.JKS, keyStoreFile, CertificateWriter.CertMode.valid);

        try {
            final CloseableHttpClient closeableHttpClient = new HttpClientBuilder().buildHttpsClient().setHostnameVerifier(null).addKeystore(file, "keyStorePwd").addTrustore(file, "keyStorePwd", false).build();
            Assert.assertNotNull(closeableHttpClient);
        } catch (final Exception e) {
            Assert.assertTrue(false);
        }
        file.delete();
    }
}
