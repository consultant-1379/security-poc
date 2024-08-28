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

import java.io.IOException;
import java.util.List;

import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Vault http client class used to manage http requests
 */
public class HttpClientUtility {

    private static final Logger logger = LoggerFactory.getLogger(HttpClientUtility.class);

    private HttpClientUtility() {
        super();
    }

    /**
     * @param httpHost
     *            host name to connect
     * @param relativePath
     *            uri path
     * @param headers
     *            headers of the rest
     * @return HttpGet object
     */
    public static HttpGet generateGet(final HttpHost httpHost, final String relativePath, final List<NameValuePair> headers) {
        final String uri = buildURI(httpHost, relativePath);
        final HttpGet httpGet = new HttpGet(uri);

        if (headers != null) {
            for (final NameValuePair header : headers) {
                httpGet.addHeader(header.getName(), header.getValue());
            }
        }
        return httpGet;
    }

    /**
     * @param httpHost
     *            host name to connect
     * @param relativePath
     *            uri path
     * @param headers
     *            headers of the rest
     * @param parameters
     *            body of the rest
     * @return HttpPut object
     */

    public static HttpPut generatePut(final HttpHost httpHost, final String relativePath, final List<NameValuePair> headers,
                                      final String parameters) {
        final String uri = buildURI(httpHost, relativePath);

        final HttpPut httpPut = new HttpPut(uri);

        if (parameters != null && !parameters.isEmpty()) {
            httpPut.setEntity(new StringEntity(parameters, "UTF-8"));
        }
        if (headers != null) {
            for (final NameValuePair header : headers) {
                httpPut.addHeader(header.getName(), header.getValue());
            }
        }

        return httpPut;
    }

    /**
     * @param httpRequest
     *            request to execute
     * @param httpClient
     *            client properties
     * @return CloseableHttpResponse
     * @throws IOException
     *             error to execute the query
     */
    public static CloseableHttpResponse executeQuery(final HttpRequestBase httpRequest, final CloseableHttpClient httpClient) throws IOException {
        CloseableHttpResponse response = null;
        response = httpClient.execute(httpRequest);
        final int status = response.getStatusLine().getStatusCode();
        logger.debug("execute Query status {}", status);
        return response;
    }

    private static String buildURI(final HttpHost httpHost, final String relativePath) {
        return String.format("%s://%s%s", httpHost.getSchemeName(), httpHost.toHostString(), relativePath);
    }
}
