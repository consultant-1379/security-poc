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

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.CertificateExtensionsResponseDTO;

/**
 * A builder class to build the Extensions details of a certificate like subjectAltName,keyUsages,keyPurposeIds and cRLDistributionPoints in certificate list JSON response.
 */
public class CertificateExtensionsResponseBuilder {

    protected String subjectAltName;
    protected List<KeyUsageType> keyUsages;
    protected List<KeyPurposeId> keyPurposeIds;
    protected List<String> cRLDistributionPoints;

    /**
     * builder method for setting subjectAltName property
     * 
     * @param subjectAltName
     * @return subjectAltName
     */
    public CertificateExtensionsResponseBuilder subjectAltName(final String subjectAltName) {

        this.subjectAltName = subjectAltName;
        return this;

    }

    /**
     * builder method for setting keyUsages property
     * 
     * @param keyUsages
     * @return keyUsages
     */
    public CertificateExtensionsResponseBuilder keyUsages(final List<KeyUsageType> keyUsages) {

        this.keyUsages = keyUsages;
        return this;

    }

    /**
     * builder method for setting keyPurposeIds property
     * 
     * @param keyPurposeIds
     * @return keyPurposeIds
     */
    public CertificateExtensionsResponseBuilder keyPurposeIds(final List<KeyPurposeId> keyPurposeIds) {

        this.keyPurposeIds = keyPurposeIds;
        return this;

    }

    /**
     * builder method for setting cRLDistributionPoint property
     * 
     * @param cRLDistributionPoint
     * @return cRLDistributionPoints
     */
    public CertificateExtensionsResponseBuilder cRLDistributionPoints(final List<String> cRLDistributionPoint) {

        this.cRLDistributionPoints = cRLDistributionPoint;
        return this;

    }

    /**
     * Return fully build Extensions details of Certificate Object.
     * 
     * @return {@link CertificateExtensionsResponseDTO} Object.
     */
    public CertificateExtensionsResponseDTO build() {

        final CertificateExtensionsResponseDTO certificateExtensionsDetails = new CertificateExtensionsResponseDTO();
        certificateExtensionsDetails.setSubjectAltName(subjectAltName);
        certificateExtensionsDetails.setKeyPurposeIds(keyPurposeIds);
        certificateExtensionsDetails.setKeyUsages(keyUsages);
        certificateExtensionsDetails.setcRLDistributionPoint(cRLDistributionPoints);
        return certificateExtensionsDetails;

    }

}
