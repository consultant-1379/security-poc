/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.api.model;


public enum CertificateStatus {
    ACTIVE, EXPIRED, REVOKED, INACTIVE;

    public String value() {
        return name();
    }

    public static CertificateStatus fromValue(final String v) {
        return valueOf(v);
    }

}
