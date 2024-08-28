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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

/**
 * Represents the certificate status.
 * 
 * @author xprabil
 * 
 */
public enum CertificateStatus {

    /**
     * When certificate generated marked as active.
     */
    ACTIVE("active", 1),

    /**
     * When certificate expired marked as expired.
     */

    EXPIRED("expired", 2),

    /**
     * When certificate revoked marked as revoked.
     */
    REVOKED("revoked", 3),

    /**
     * When certificate is updated, old certificate will be marked as inactive.
     */
    INACTIVE("inactive", 4);

    private int id;

    public int getId() {
        return this.id;
    }

    private String certStatus;

    CertificateStatus(final String status, final int id) {
        certStatus = status;
        this.id = id;
    }

    public String value() {
        return certStatus;
    }

    public static CertificateStatus fromValue(final String v) {
        return valueOf(v);
    }

    public static CertificateStatus getStatus(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final CertificateStatus certificateStatus : CertificateStatus.values()) {
            if (id.equals(certificateStatus.getId())) {
                return certificateStatus;
            }
        }

        throw new IllegalArgumentException("No matching type for id " + id);
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

}
