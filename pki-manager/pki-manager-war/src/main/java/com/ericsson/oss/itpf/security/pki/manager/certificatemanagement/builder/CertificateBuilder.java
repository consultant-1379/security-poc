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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.*;

/**
 * A builder class to build the basic details and extension details of a certificate for filter the certificate details in certificate list JSON response.
 */
public class CertificateBuilder {

    CertificateBasicDetailsDTO certificateBasicDetailsDTO;
    CertificateExtensionsResponseDTO certificateExtensionsResponseDTO;

    /**
     * builder method for setting certificateBasicDetails property
     * 
     * @param certificateBasicDetailsDTO
     * @return certificateBasicDetailsDTO
     */
    public CertificateBuilder certificateBasicDetails(final CertificateBasicDetailsDTO certificateBasicDetailsDTO) {

        this.certificateBasicDetailsDTO = certificateBasicDetailsDTO;
        return this;

    }

    /**
     * builder method for setting certificateExtensionsResponseDTO property
     * 
     * @param certificateExtensionsResponseDTO
     * @return certificateExtensionsResponseDTO
     */
    public CertificateBuilder certificateExtensionsResponse(final CertificateExtensionsResponseDTO certificateExtensionsResponseDTO) {

        this.certificateExtensionsResponseDTO = certificateExtensionsResponseDTO;
        return this;

    }

    /**
     * Return fully build Certificate Object with basic details and extension details.
     * 
     * @return {@link CertificateResponseDTO} Object
     * 
     */
    public CertificateResponseDTO build() {

        final CertificateResponseDTO certificateResponseFilter = new CertificateResponseDTO();
        certificateResponseFilter.setDetails(certificateBasicDetailsDTO);
        certificateResponseFilter.setExtensions(certificateExtensionsResponseDTO);
        return certificateResponseFilter;
    }
}
