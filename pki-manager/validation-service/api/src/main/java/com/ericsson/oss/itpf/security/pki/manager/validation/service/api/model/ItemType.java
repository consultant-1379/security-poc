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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model;

/**
 * Different services
 */
public enum ItemType {
    CERTIFICATE_PROFILE("certificateprofile"), ENTITY_PROFILE("entityprofile"), TRUST_PROFILE("trustprofile"), CA_ENTITY("caentity"), ENTITY("entity"), X509CERTIFICATE("x509certificate"), GENERATE_CSR(
            "exportcsr"), ENTITY_OTP("entityotp"), UNKNOWN("unknown");

    private String value;

    ItemType(final String value) {
        this.value = value;
    }

    /**
     * get String value of ItemType
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(final ItemType itemType) {
        return super.equals(itemType);
    }

    /**
     * Get ItemType Enum from given String value.
     * 
     * @param value
     * @return Corresponding Enum
     */
    public static ItemType fromValue(final String value) {
        for (final ItemType itemType : ItemType.values()) {
            if (itemType.value.equalsIgnoreCase(value)) {
                return itemType;
            }
        }
        throw new IllegalArgumentException("Invalid Item Type!");
    }
}
