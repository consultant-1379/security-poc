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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

public enum CredentialManagerConnectorManagedType {

    HTTPS_CONNECTOR("httpsConnector"), UNDEFINED("undefined");

    private final String value;

    CredentialManagerConnectorManagedType(final String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static CredentialManagerConnectorManagedType fromValue(final String v) {
        for (final CredentialManagerConnectorManagedType c : CredentialManagerConnectorManagedType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
