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
package com.ericsson.oss.itpf.security.pki.manager.common.enums;

/**
 * This enum describes for both ipv4 and ipv6 sbLoadBalancer addresses.
 * 
 * @author xchowja
 *
 */
public enum InternetProtocolVersionType {
    IPv4("ipv4"), IPv6("ipv6");

    private final String value;

    InternetProtocolVersionType(final String value) {
        this.value = value;
    }

    /**
     * get String value of InternetProtocolVersionType
     * 
     * @return value
     */
    public String getValue() {
        return value;
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

    /**
     * Get InternetProtocolVersionType Enum from given String value.
     * 
     * @param value
     * @return Corresponding Enum
     */
    public static InternetProtocolVersionType fromValue(final String value) {
        for (final InternetProtocolVersionType internetProtocolVersionType : InternetProtocolVersionType.values()) {
            if (internetProtocolVersionType.value.equalsIgnoreCase(value)) {
                return internetProtocolVersionType;
            }
        }
        throw new IllegalArgumentException("Invalid Internet Protocol Version Type!");
    }
}
