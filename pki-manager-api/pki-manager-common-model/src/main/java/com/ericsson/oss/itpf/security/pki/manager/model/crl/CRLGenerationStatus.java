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
package com.ericsson.oss.itpf.security.pki.manager.model.crl;

/**
 * This is an ENUM class that holds the CRLGeneration Status constants
 * 
 * @author xramdag
 *
 */
public enum CRLGenerationStatus {

    CA_ENTITY_NOT_FOUND("CAEntity is not found"), CERTIFICATE_NOT_FOUND("Certificate is not found"), CRLGENERATION_INFO_NOT_VALID("CRLGenerationInfo is not valid"), CRLGENERATION_INFO_NOT_FOUND(
            "CRLGenerationInfo is not found"), GENERATE_CRL_ERROR("Internal Service Error while generating CRL"), CRL_GENERATION_SUCCESSFUL("CRL(s) generated successfully"), NO_VALID_CERTIFICATE_FOUND(
            "Valid Certificates are not found"), EXTERNAL_CA_ENTITY("CA is an external CA"), INVALID_ENTITY_ATTRIBUTE("Invalid attribute found in entity"), INVALID_PROFILE_ATTRIBUTE(
            "Invalid attribute found in profile");

    private String value;

    CRLGenerationStatus(final String value) {
        this.value = value;
    }

    /**
     * get String value of CRLGenerationStatus
     * 
     * @return value
     */
    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return super.toString();
    }

    public boolean equals(final CRLGenerationStatus crlGenerationStatus) {
        return super.equals(crlGenerationStatus);
    }

    /**
     * Get CRLGenerationStatus Enum from given String value.
     * 
     * @param value
     * @return CRLGenerationStatus
     */
    public static CRLGenerationStatus fromValue(final String value) {
        for (final CRLGenerationStatus crlGenerationStatus : CRLGenerationStatus.values()) {
            if (crlGenerationStatus.value.equalsIgnoreCase(value)) {
                return crlGenerationStatus;
            }
        }
        throw new IllegalArgumentException("Invalid CRL Generation Status!");
    }

}
