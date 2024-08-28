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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateRequestData;

public class CertificateRequestSetUpData {

    private static final String cSR = "Sample CSR";

    /**
     * Prepares {@link CertificateRequestData} to check for equals method.
     * 
     * @return {@link CertificateRequestData} to compare.
     */
    public CertificateRequestData getCSRForEqual() {
        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setId(1);
        certificateRequestData.setStatus(1);
        certificateRequestData.setCsr(cSR.getBytes());
        return certificateRequestData;
    }

    /**
     * Prepares {@link CertificateRequestData} to check for equals method.
     * 
     * @return {@link CertificateRequestData} to compare.
     */
    public CertificateRequestData getCSRForNotEqual() {
        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setId(2);
        certificateRequestData.setStatus(3);
        certificateRequestData.setCsr(cSR.getBytes());
        return certificateRequestData;
    }
}
