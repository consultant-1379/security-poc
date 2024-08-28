/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class CertificateSummaryTest {

    @SuppressWarnings("static-access")
    @Test
    public void testCertificateSummary() {

        // prepare data
        String issuerDN = "IssuerName";
        String subjectDN = "SubjectName";
        String certificateSN = "123456789";
        CertificateStatus certificateStatus = CertificateStatus.ACTIVE;

        // instantiate CertificateSummary
        CertificateSummary certSummary = new CertificateSummary(issuerDN, subjectDN, certificateSN, certificateStatus);

        // check
        assertTrue(issuerDN.equals(certSummary.getIssuerDN()));
        assertTrue(subjectDN.equals(certSummary.getSubjectDN()));
        assertTrue(certificateSN.equals(certSummary.getCertificateSN()));
        assertTrue(certificateStatus.equals(certSummary.getCertificateStatus()));

        // modify values
        certSummary.setIssuerDN("IssuerName_2");
        certSummary.setSubjectDN("SubjectName_2");
        certSummary.setCertificateSN("123456788");
        certSummary.setCertificateStatus(CertificateStatus.INACTIVE);

        // second check
        assertTrue("IssuerName_2".equalsIgnoreCase(certSummary.getIssuerDN()));
        assertTrue("SubjectName_2".equalsIgnoreCase(certSummary.getSubjectDN()));
        assertTrue("123456788".equalsIgnoreCase(certSummary.getCertificateSN()));
        assertTrue(CertificateStatus.INACTIVE == certSummary.getCertificateStatus());
        assertTrue(certSummary.getSerialversionuid() == CertificateSummary.getSerialversionuid());

    }
}
