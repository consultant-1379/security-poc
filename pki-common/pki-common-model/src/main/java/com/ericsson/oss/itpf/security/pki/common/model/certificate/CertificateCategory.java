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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

/**
 * Enum for representing the certificate for which entity it belongs to.
 * 
 * @author tcsviku
 * 
 */
public enum CertificateCategory {

    /**
     * When certificate is of Internal CA.
     */
    INTERNAL_CA("internalca", 1),

    /**
     * When certificate is of External CA.
     */
    EXTERNAL_CA("externalca", 2),

    /**
     * When certificate is of End Entity.
     */
    ENTITY("entity", 3);

    private int id;
    private String entityType;

    CertificateCategory(final String entityType, final int id) {
        this.entityType = entityType;
        this.id = id;
    }

    public int getId() {
        return this.id;
    }

    public String value() {
        return entityType;
    }

    public static CertificateCategory fromValue(final String v) {
        return valueOf(v);
    }

    public static CertificateCategory getEntityType(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final CertificateCategory certificateCategory : CertificateCategory.values()) {
            if (id.equals(certificateCategory.getId())) {
                return certificateCategory;
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
