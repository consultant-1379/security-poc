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
 * This enum incapsulate JSON values for the CredentialManagerController monitoring actions.
 */
public enum CredentialManagerMonitoringAction {
    ENABLE("enable"), DISABLE("disable");

    private String text;

    private CredentialManagerMonitoringAction(final String text) {
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
     * Convert a string (case insensitive) into a CredentialManagerMonitoringAction object
     *
     * @param String
     *            value to convert
     * @return the converted CredentialManagerMonitoringAction
     * @throws IllegalArgumentException
     *             if {@code value} does not match any enum value
     */
    public static CredentialManagerMonitoringAction fromString(final String text) {
        for (final CredentialManagerMonitoringAction b : CredentialManagerMonitoringAction.values()) {
            if (b.text.equalsIgnoreCase(text)) {
                return b;
            }
        }
        throw new IllegalArgumentException(text + " does not match any CredentialManagerMonitoringAction valid value");
    }
}