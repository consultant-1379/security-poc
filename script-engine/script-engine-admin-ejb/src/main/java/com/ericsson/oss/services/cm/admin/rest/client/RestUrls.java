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
package com.ericsson.oss.services.cm.admin.rest.client;

import com.ericsson.oss.services.cm.admin.rest.client.common.RestRequest;

/**
 * Enumeration class uses to build url for {@link RestRequest}
 */
public enum RestUrls {

    CONFIGURATION_SERVICE_UPDATE_PIB("pib/configurationService", 8080, "updateConfigParameterValue?paramName="),
    CONFIGURATION_SERVICE_GET_PIB("pib/configurationService", 8080, "getConfigParameterValue?paramName="),
    CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB("pib/configurationService", 8080, "getAllConfigParametersInScope");

    private static final String HTTP_PROTOCOL = "http";
    private static final String CMSERV_ALIAS = "cli-service";
    private static final String INTERNAL_URL = "INTERNAL_URL";

    private final String serverAddress;
    private final String serviceContext;

    RestUrls(final String namespace, final int port, final String resource) {
        this.serverAddress = HTTP_PROTOCOL + "://" + CMSERV_ALIAS + ":" + port;
        this.serviceContext = "/" + namespace + "/" + resource;
    }

    /**
     * @return full url in format: http://haproxy-int:{port}/{namespace}/{resource}
     */
    public String getFullUrl() {
        return System.getProperty(INTERNAL_URL, this.serverAddress) + serviceContext;
    }

    /**
     * @return url's service context part in format: /{namespace}/{resource}
     */
    public String getServiceContext() {
        return this.serviceContext;
    }
}
