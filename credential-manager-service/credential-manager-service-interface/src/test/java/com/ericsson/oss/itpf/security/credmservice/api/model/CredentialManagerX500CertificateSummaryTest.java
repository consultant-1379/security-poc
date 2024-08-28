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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

public class CredentialManagerX500CertificateSummaryTest {

    @Test
    public void testCredentialManagerX500CertificateSummary() {

        X500Principal subjectX500Principal = new X500Principal("CN=subject");
        X500Principal issuerX500Principal = new X500Principal("CN=issuer");
        BigInteger certificateSN = new BigInteger("123456789");
        CredentialManagerCertificateStatus certificateStatus = CredentialManagerCertificateStatus.ACTIVE;

        CredentialManagerX500CertificateSummary credManx500Sum_1 = new CredentialManagerX500CertificateSummary();
        credManx500Sum_1.setIssuerX500Principal(issuerX500Principal);
        credManx500Sum_1.setSubjectX500Principal(subjectX500Principal);
        credManx500Sum_1.setCertificateSN(certificateSN);
        credManx500Sum_1.setCertificateStatus(certificateStatus);

        CredentialManagerX500CertificateSummary credManx500Sum_2 = new CredentialManagerX500CertificateSummary(subjectX500Principal, issuerX500Principal, certificateSN, certificateStatus);

        assertTrue(credManx500Sum_1.getIssuerX500Principal().equals(credManx500Sum_2.getIssuerX500Principal()));
        assertTrue(credManx500Sum_1.getSubjectX500Principal().equals(credManx500Sum_2.getSubjectX500Principal()));
        assertTrue(credManx500Sum_1.getCertificateSN().equals(credManx500Sum_2.getCertificateSN()));
        assertTrue(credManx500Sum_1.getCertificateStatus().equals(credManx500Sum_2.getCertificateStatus()));
    }
}
