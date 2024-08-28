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
package com.ericsson.oss.itpf.security.pki.common.model.crl;

/**
 * This Class is used to represent CRL Status
 * <ul>
 * <li>LATEST: Status is set to LATEST once the CRL is generated for CA.</li>
 * <li>OLD: Status is set to OLD once the CRL is reissued.</li>
 * <li>INVALID: Status is set to INVALID,if the issuer certificate is revoked.</li>
 * <li>EXPIRED: Status is set to EXPIRED when CRL is expired.</li>
 * </ul>
 * 
 */

public enum CRLStatus {

    LATEST(1), OLD(2), INVALID(3), EXPIRED(4);

    private int id;

    /**
     * Get Enum value from integer.
     * 
     * @param id
     * @return CRLStatus Enum
     */
    private CRLStatus(final int id) {
        this.id = id;
    }

    /**
     * @return
     */
    public int getId() {
        return this.id;
    }

    /**
     * @return
     */
    public String value() {
        return name();
    }

    /**
     * Get Enum value from String.
     * 
     * @param value
     * @return CRLStatus Enum
     */
    public static CRLStatus fromValue(final String value) {
        return valueOf(value);
    }

    /**
     * Get Enum value from integer.
     * 
     * @param id
     * @return CRLStatus Enum
     */
    public static CRLStatus getStatus(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final CRLStatus cRLStatus : CRLStatus.values()) {
            if (id.equals(cRLStatus.getId())) {
                return cRLStatus;
            }
        }

        throw new IllegalArgumentException("No matching status for id " + id);
    }

    @Override
    public String toString() {
        return super.toString();
    }

}