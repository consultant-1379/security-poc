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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter;

import com.fasterxml.jackson.annotation.JsonFilter;

/**
 * Class is used for apply the JSON filter and return the both basic details like certificateIds,subjectDN,expiryDateFrom,expiryDateTo,issuerDN,entityTypes,keySize,certificateStatus and extensions
 * details like subjectAltName,keyUsages,keyPurposeIds and cRLDistributionPoints in JSON response.
 */
@JsonFilter("certificate")
public class CertificateResponseDTO {

    CertificateBasicDetailsDTO details;
    CertificateExtensionsResponseDTO extensions;

    /**
     * @return the details
     */
    public CertificateBasicDetailsDTO getDetails() {
        return details;
    }

    /**
     * @param details
     *            the details to set
     */
    public void setDetails(final CertificateBasicDetailsDTO details) {
        this.details = details;
    }

    /**
     * @return the extensions
     */
    public CertificateExtensionsResponseDTO getExtensions() {
        return extensions;
    }

    /**
     * @param extensions
     *            the extensions to set
     */
    public void setExtensions(final CertificateExtensionsResponseDTO extensions) {
        this.extensions = extensions;
    }

}
