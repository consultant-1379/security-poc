/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.utils;

import javax.inject.Inject;

import org.slf4j.Logger;

/**
 * This class is used to build TrustDistributionPoint URL.
 * 
 * @author tcsramc
 *
 */
public class TDPSURLBuilder {

    @Inject
    Logger logger;

    private final static String URL_SEPARATOR = "/";
    private final static String HTTP_PROTOCOL = "http://";
    private String entityType;

    private String entityName;
    private String serialNumber;
    private String host;
    private String issuerName;
    private String certificateStatus;

    //TODO : Flexible URL implementation will be taken under the following user story 
    //http://jira-nam.lmera.ericsson.se/browse/TORF-80272 
    final private String urlFormatter = HTTP_PROTOCOL + "%s" + URL_SEPARATOR + "pki-ra-tdps" + URL_SEPARATOR + "%s" + URL_SEPARATOR + "%s" + URL_SEPARATOR + "%s" + URL_SEPARATOR + "%s" + URL_SEPARATOR + "%s";

    /**
     * @param host
     *            the host to set
     */
    public TDPSURLBuilder host(final String host) {
        this.host = host;
        return this;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public TDPSURLBuilder serialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public TDPSURLBuilder entityType(final String entityType) {
        this.entityType = entityType;
        return this;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    public TDPSURLBuilder entityName(final String entityName) {
        this.entityName = entityName;
        return this;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public TDPSURLBuilder issuerName(final String issuerName) {
        this.issuerName = issuerName;
        return this;
    }

    /**
     * @param certificateStatus
     *            the certificateStatus to set
     */
    public TDPSURLBuilder certificateStatus(final String certificateStatus) {
        this.certificateStatus = certificateStatus;
        return this;
    }

    /**
     * This method is used to build TrustDistributionPoint URL based on entity and Serial Number.
     * 
     * @return returns TrustDistributionPoint URL
     * 
     */
    public String build() {
        final String tdpsURL = String.format(urlFormatter, host, entityType, entityName, serialNumber, certificateStatus, issuerName);
        return tdpsURL;
    }
}
