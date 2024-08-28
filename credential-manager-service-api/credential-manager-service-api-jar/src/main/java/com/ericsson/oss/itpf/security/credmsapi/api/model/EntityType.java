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

public enum EntityType {
    ENTITY("entity"), CA_ENTITY("caentity");

    String value;

    EntityType(final String value) {
        this.value = value;
    }

    /**
     * get String value of EntityType
     * 
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * get the Enum from String value.
     * 
     * @param value
     * @return Corresponding Enum
     */
    public static EntityType fromValue(final String value) {
        for (final EntityType entityType : EntityType.values()) {
            if (entityType.value.equalsIgnoreCase(value)) {
                return entityType;
            }
        }
        throw new IllegalArgumentException("Invalid Entity Type");
    }

}
