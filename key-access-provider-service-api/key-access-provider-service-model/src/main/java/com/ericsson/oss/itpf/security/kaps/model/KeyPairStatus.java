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
package com.ericsson.oss.itpf.security.kaps.model;

/**
 * Model that contains the status of the key pair.
 * 
 */
public enum KeyPairStatus {

    /**
     * When certificate generated marked as active.
     */
    ACTIVE("active", 1),

    /**
     * When certificate is updated, old certificate will be marked as inactive.
     */
    INACTIVE("inactive", 2);

    private int id;

    public int getId() {
        return this.id;
    }

    private String keyPairStatus;

    KeyPairStatus(final String status, final int id) {
        keyPairStatus = status;
        this.id = id;
    }

    /**
     * @return key pair status value
     */
    public String value() {
        return keyPairStatus;
    }

    /**
     * @param v
     *            value of the key pair status
     * @return enum from the value
     */
    public static KeyPairStatus fromValue(final String v) {
        return valueOf(v);
    }

    /**
     * @param id
     *            id of the key pair status
     * @return enum from the id
     */
    public static KeyPairStatus getStatus(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final KeyPairStatus keyPairStatus : KeyPairStatus.values()) {
            if (id.equals(keyPairStatus.getId())) {
                return keyPairStatus;
            }
        }

        throw new IllegalArgumentException("No matching type for id " + id);
    }

    /**
     * String representation of the enum
     */
    @Override
    public String toString() {
        return super.toString();
    }

}
