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
package com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps;

/**
 * This is an ENUM class holds the CRL Publish Unpublish Status constants
 * 
 * @author xjagcho
 *
 */
public enum CRLPublishUnpublishStatus {
    CA_ENTITY_NOT_FOUND("CAEntity is not found"), CRL_INFO_NOT_FOUND("CRLInfo(s) are not found"), SENT_FOR_PUBLISH("CRL(s) are sent for publish"), SENT_FOR_UNPUBLISH("CRL(s) are sent for unpublish"), VALID_CRL_NOT_FOUND(
            "No valid CRL found"), EXTERNAL_CA("CA is an external CA"), INVALID_ENTITY_ATTRIBUTE("Invalid attribute found in entity"), INVALID_PROFILE_ATTRIBUTE("Invalid attribute found in profile");

    private String value;

    CRLPublishUnpublishStatus(final String value) {
        this.value = value;
    }

    /**
     * get String value of CRLPublishUnpublishStatus
     * 
     * @return value
     */
    public String getValue() {
        return value;
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(final CRLPublishUnpublishStatus crlPublishUnpublishStatus) {
        return super.equals(crlPublishUnpublishStatus);
    }

    /**
     * Get CRLPublishUnpublishStatus Enum from given String value.
     * 
     * @param value
     * @return Corresponding Enum
     */
    public static CRLPublishUnpublishStatus fromValue(final String value) {
        for (final CRLPublishUnpublishStatus crlPublishUnpublishStatus : CRLPublishUnpublishStatus.values()) {
            if (crlPublishUnpublishStatus.value.equalsIgnoreCase(value)) {
                return crlPublishUnpublishStatus;
            }
        }
        throw new IllegalArgumentException("Invalid CRL Publish UnPublish Status!");
    }
}
