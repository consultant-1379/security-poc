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

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

/**
 * Http Connection Factory class used to manage http client connection
 */
@ApplicationScoped
public class HttpConnectionFactory {

    HttpClientConnectionManager poolingConnManager;

    @PostConstruct
    public void init() {
        poolingConnManager = new PoolingHttpClientConnectionManager();
    }

    /**
     *
     * @return a CloseableHttpClient setting a pool of connections
     */
    public CloseableHttpClient getClient() {
        return HttpClients.custom().setConnectionManager(poolingConnManager).build();
    }
}
