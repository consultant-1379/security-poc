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
 * Enum consisting of all the metric types for in Instrumentation service
 * 
 */
public enum MetricType {
    GENERATE, RENEW, REKEY, REVOKE, CREATE, UPDATE, DELETE, GET, UNKNOWN;

    @Override
    public String toString() {
        return super.toString();
    }
}
