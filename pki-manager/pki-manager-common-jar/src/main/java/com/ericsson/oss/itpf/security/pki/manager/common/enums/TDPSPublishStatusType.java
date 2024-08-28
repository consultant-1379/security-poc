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
package com.ericsson.oss.itpf.security.pki.manager.common.enums;

/**
 * This enum describes whether the certificate should be published or unpublished.
 * 
 * @author tcsdemi
 *
 */
public enum TDPSPublishStatusType {
    PUBLISH("PUBLISH"), UNPUBLISH("UNPUBLISH"), UNKNOWN("UNKNOWN");

    private final String name;

    private TDPSPublishStatusType(final String name) {
        this.name = name;
    }

    public String getValue() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

}
