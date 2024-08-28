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
package com.ericsson.oss.itpf.security.pki.common.model;

/**
 * Represents CA Status
 * <ul>
 * <li>New: Status is set to new when CA is created.</li>
 * <li>Active: Status is set to active once the certificate is generated for CA.</li>
 * <li>InActive: Status is set to inactive when certificate is revoked.
 * <li>
 * <li>Deleted: Status is set to deleted when CA is deleted.</li>
 * </ul>
 * 
 */

public enum CAStatus {
    NEW("new", 1), ACTIVE("active", 2), INACTIVE("inactive", 3), DELETED("deleted", 4);

    private int id;

    public int getId() {
        return this.id;
    }

    private String caStatus;

    CAStatus(final String status, final int id) {
        caStatus = status;
        this.id = id;
    }

    /**
     * Get String value of Enum
     * 
     * @return String value of enum.
     */
    public String value() {
        return caStatus;
    }

    /**
     * Get Enum value from String.
     * 
     * @param value
     * @return CAStatus Enum
     */
    public static CAStatus fromValue(final String v) {
        return valueOf(v);
    }

    /**
     * Get Enum value from id.
     * 
     * @param id
     * @return CAStatus Enum
     */
    public static CAStatus getStatus(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final CAStatus caStatus : CAStatus.values()) {
            if (id.equals(caStatus.getId())) {
                return caStatus;
            }
        }

        throw new IllegalArgumentException("No matching status for id " + id);
    }

    @Override
    public String toString() {
        return super.toString();
    }

}
