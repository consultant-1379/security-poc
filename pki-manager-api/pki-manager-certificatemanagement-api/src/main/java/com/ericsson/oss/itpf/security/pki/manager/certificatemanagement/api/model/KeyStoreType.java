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

package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model;

/**
 * KeyStore types that are supported in the system.
 * 
 */
public enum KeyStoreType {

    JKS("jks"), PKCS12("pkcs12"), JCEKS("jceks"), PEM("pem");

    String value;

    KeyStoreType(final String type) {

        value = type;
    }

    /**
     * Get String value for key store type.
     * 
     * @return String value of keyStoreType
     */
    public String value() {

        return value;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
