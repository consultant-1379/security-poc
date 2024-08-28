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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

/**
 * This enum contains the Revocation Reasons and its values.
 */

public enum PkiRevocationReasonType {

    UNSPECIFIED("0", "unspecified"), KEY_COMPROMISE("1", "keyCompromise"), CA_COMPROMISE("2", "cACompromise"), AFFILIATION_CHANGED("3", "affiliationChanged"), SUPERSEDED("4", "superseded"), CESSATION_OF_OPERATION(
            "5", "cessationOfOperation"), CERTIFICATE_HOLD("6", "certificateHold"), REMOVE_FROM_CRL("8", "removeFromCRL"), PRIVILEGE_WITHDRAWN("9", "privilegeWithdrawn"), AA_COMPROMISE("10",
            "aACompromise");

    final String reasonCode;
    final String reasonText;

    /**
     * @param reasonCode
     * @param reasonText
     */
    private PkiRevocationReasonType(final String reasonCode, final String reasonText) {
        this.reasonCode = reasonCode;
        this.reasonText = reasonText;
    }

    /**
     * @return the reasonCode
     */
    public String getReasonCode() {
        return reasonCode;
    }

    /**
     * @return the reasonText
     */
    public String getReasonText() {
        return reasonText;
    }

    /**
     * Get the String value of this PkiRevocationReasonType
     * 
     * @return reasonCode
     */
    @Override
    public String toString() {
        return String.valueOf(this.reasonCode) + "-" + String.valueOf(this.reasonText);
    }

    /**
     * Get the PkiRevocationReasonType value from the ReasonCode.
     * 
     * @param ReasonCode
     * @return reasonType
     * @throws IllegalArgumentException
     */
    public static PkiRevocationReasonType fromReasonCode(final String reasonCode) {
        for (final PkiRevocationReasonType reasonType : PkiRevocationReasonType.values()) {
            if (reasonType.getReasonCode().equals(reasonCode)) {

                return reasonType;
            }
        }
        throw new IllegalArgumentException("Reason code not supported");
    }

    /**
     * Get the PkiRevocationReasonType value from the ReasonText.
     * 
     * @param ReasonText
     * @return reasonType
     * @throws IllegalArgumentException
     */
    public static PkiRevocationReasonType fromReasonText(final String reasonText) {
        for (final PkiRevocationReasonType reasonType : PkiRevocationReasonType.values()) {
            if (reasonType.getReasonText().equalsIgnoreCase(reasonText)) {

                return reasonType;
            }
        }
        throw new IllegalArgumentException("Reason text not supported");
    }

}
