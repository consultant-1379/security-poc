/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.types;

/**
 * Enum consisting of all the metric groups for in Instrumentation service
 * 
 */
public enum MetricGroup {

    ENTITYMGMT("EntityManagement"), CACERTIFICATEMGMT("CACertificateManagement"), ENTITYCERTIFICATEMGMT("EntityCertificateManagement"), CRLMGMT("CRLManagement"), REVOCATIONMGMT("RevocationManagement"), UNKNOWN(
            "Unknown");

    private final String name;

    private MetricGroup(final String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static MetricGroup getMetricGroup(final String name) {
        for (final MetricGroup actionType : MetricGroup.values()) {
            if (actionType.getName().equals(name)) {
                return actionType;
            }
        }
        return MetricGroup.UNKNOWN;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}