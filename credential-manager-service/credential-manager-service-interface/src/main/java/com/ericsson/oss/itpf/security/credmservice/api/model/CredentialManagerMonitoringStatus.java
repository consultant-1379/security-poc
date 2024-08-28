/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;

/**
 * This enum incapsulate JSON values for the CredentialManagerController monitoring status.
 */
public enum CredentialManagerMonitoringStatus {
    ENABLED("Enabled"), ENABLING("Enabling"), DISABLED("Disabled"), DISABLING("Disabling"), EMPTY("Empty");

    private String text;

    private CredentialManagerMonitoringStatus(final String text) {
        this.text = text;
    }

    /**
     * Returns a String representing the literal value of the object
     *
     * @return literal value representation
     */
    public String getText() {
        return this.text;
    }

    /**
     * Convert a string (case insensitive) into a CredentialManagerMonitoringStatus object
     *
     * @param String
     *            value to convert
     * @return the converted CredentialManagerMonitoringStatus
     * @throws IllegalArgumentException
     *             if {@code value} does not match any enum value
     */
    public static CredentialManagerMonitoringStatus fromString(final String text) {
        for (final CredentialManagerMonitoringStatus b : CredentialManagerMonitoringStatus.values()) {
            if (b.text.equalsIgnoreCase(text)) {
                return b;
            }
        }
        throw new IllegalArgumentException(text + " does not match any CredentialManagerMonitoringStatus valid value");
    }
}