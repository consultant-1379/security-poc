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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

/**
 * Represents the type of update for certificate.
 * 
 * @author xprabil
 * 
 */
public enum RequestType {

    /**
     * Used in case of new certificate generation.
     */
    NEW("new", 1),

    /**
     * Type of enrollment when existing keys used to generate the certificate. Mainly used in case of certificate is expired.
     */
    RENEW("renew", 2),

    /**
     * Type of enrollment when existing keys are used to generate the certificate, but with some modification in certificate attributes.
     */
    MODIFY("modify", 3),

    /**
     * Type of enrollment when new keys needs to be generated in case of certificate generation. Mainly used when keys of the entity/CA are compromised.
     */
    REKEY("rekey", 4);

    int id;

    public int getId() {
        return this.id;
    }

    private String requestType;

    RequestType(final String type, final int id) {
        requestType = type;
        this.id = id;
    }

    public String value() {
        return requestType;
    }

    public static RequestType fromValue(final String v) {
        return valueOf(v);
    }

    public static RequestType getType(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final RequestType requestType : RequestType.values()) {
            if (id.equals(requestType.getId())) {
                return requestType;
            }
        }

        throw new IllegalArgumentException("No matching type for id " + id);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return super.toString();
    }

}
