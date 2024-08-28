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
 * 
 * This enum contains supported versions of a CRL.
 * 
 */

public enum CRLVersion {
    V2(2);

    private int value;

    CRLVersion(final int value) {
        this.value = value;
    }

    /**
     * Get Version Id value.
     * 
     * @return id value
     */
    public int value() {
        return value;
    }

    /**
     * Get Version Enum from value
     * 
     * @param value
     * @return Corresponding Version Enum
     */
    public static CRLVersion fromValue(final int v) {
        for (final CRLVersion c : CRLVersion.values()) {
            if (c.value == v) {
                return c;
            }
        }
        throw new IllegalArgumentException(Integer.toString(v));
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
