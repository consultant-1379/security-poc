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
package com.ericsson.oss.itpf.security.pki.common.model.crl.revocation;

/**
 * This enum contains the Revocation Reasons which are defined in RFC 5280.
 */
public enum RevocationReason {

    UNSPECIFIED(0), KEY_COMPROMISE(1), CA_COMPROMISE(2), AFFILIATION_CHANGED(3), SUPERSEDED(4), CESSATION_OF_OPERATION(5), CERTIFICATE_HOLD(6), REMOVE_FROM_CRL(8), PRIVILEGE_WITHDRAWN(9), AA_COMPROMISE(10); 

    private int revocationReason;

    RevocationReason(final int value) {
        this.revocationReason = value;
    }

    public static RevocationReason fromValue(final String v) {
        return valueOf(v);
    }

    /**
     * @return revocationReason
     */
    public int getRevocationReason() {
        return revocationReason;
    }

    /**
     *
     * @param value
     * @return RevocationReason
     */
    public static RevocationReason getNameByValue(final int value) {
        for (final RevocationReason reason : RevocationReason.values()) {
            if (reason.revocationReason == value) {
                return reason;
            }
        }
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return name();
    }

}
