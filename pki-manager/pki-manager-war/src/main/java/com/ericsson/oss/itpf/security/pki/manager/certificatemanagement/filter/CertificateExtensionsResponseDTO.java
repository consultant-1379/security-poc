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

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.fasterxml.jackson.annotation.JsonFilter;

/**
 * Class is used for apply the JSON filter and return the Extensions details of certificate like subjectAltName,keyUsages,keyPurposeIds and cRLDistributionPoints JSON response.
 */
@JsonFilter("extensions")
public class CertificateExtensionsResponseDTO implements Serializable {

    private static final long serialVersionUID = 1L;
    protected String subjectAltName;
    private List<KeyUsageType> keyUsages;
    private List<KeyPurposeId> keyPurposeIds;
    private List<String> cRLDistributionPoints;

    /**
     * @return the subjectAltName
     */
    public String getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltName(final String subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    /**
     * @return the keyUsages
     */
    public List<KeyUsageType> getKeyUsages() {
        return keyUsages;
    }

    /**
     * @param keyUsages
     *            the keyUsages to set
     */
    public void setKeyUsages(final List<KeyUsageType> keyUsages) {
        this.keyUsages = keyUsages;
    }

    /**
     * @return the keyPurposeIds
     */
    public List<KeyPurposeId> getKeyPurposeIds() {
        return keyPurposeIds;
    }

    /**
     * @param keyPurposeIds
     *            the keyPurposeIds to set
     */
    public void setKeyPurposeIds(final List<KeyPurposeId> keyPurposeIds) {
        this.keyPurposeIds = keyPurposeIds;
    }

    /**
     * @return the cRLDistributionPoint
     */
    public List<String> getcRLDistributionPoint() {
        return cRLDistributionPoints;
    }

    /**
     * @param cRLDistributionPoint
     *            the cRLDistributionPoint to set
     */
    public void setcRLDistributionPoint(final List<String> cRLDistributionPoint) {
        this.cRLDistributionPoints = cRLDistributionPoint;
    }

}