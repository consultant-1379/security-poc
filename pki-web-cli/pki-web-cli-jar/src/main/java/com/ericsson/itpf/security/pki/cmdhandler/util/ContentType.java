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
package com.ericsson.itpf.security.pki.cmdhandler.util;

/**
 * Content/MIME (Multipurpose Internet Mail Extensions) types for the formats in the system
 * 
 * @author xpranma
 *
 */
public enum ContentType {

    JKS("application/octet-stream"), P12("application/x-pkcs12"), JCEKS("application/octet-stream"), PEM("application/x-pem-file"), DER("application/x-x509-ca-cert"), CER("application/Cert");

    String value;

    ContentType(final String type) {

        value = type;
    }

    /**
     * Get String value for Content type.
     * 
     * @return String value of ContentType.
     */
    public String value() {

        return value;
    }

    @Override
    public String toString() {
        return super.toString();
    }

}
