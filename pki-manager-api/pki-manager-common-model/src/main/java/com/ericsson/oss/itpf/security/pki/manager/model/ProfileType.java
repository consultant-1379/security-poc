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
package com.ericsson.oss.itpf.security.pki.manager.model;

/**
 * Supported types of Profiles.
 */
public enum ProfileType {
    CERTIFICATE_PROFILE("certificateprofile"), TRUST_PROFILE("trustprofile"), ENTITY_PROFILE("entityprofile");

    private final String value;

    ProfileType(final String value) {
        this.value = value;
    }

    /**
     * get String value of ProfileType
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
     * Get ProfileType Enum from given String value.
     * 
     * @param value
     * @return Corresponding Enum
     */
    public static ProfileType fromValue(final String value) {
        for (final ProfileType profileType : ProfileType.values()) {
            if (profileType.value.equalsIgnoreCase(value)) {
                return profileType;
            }
        }
        throw new IllegalArgumentException("Invalid Profile Type!");
    }
}
