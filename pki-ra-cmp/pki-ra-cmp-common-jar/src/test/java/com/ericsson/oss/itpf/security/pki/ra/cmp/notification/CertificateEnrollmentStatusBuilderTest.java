/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import java.util.Arrays;

import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateEnrollmentStatusBuilderTest {

    @InjectMocks
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    private static String subjectName_OAM = "CN=LTE02ERBS00002-oam,C=SE,O=ERICSSON,OU=BUCI DUAC NAM";
    private static String issuerName_OAM = "NE_OAM_CA";
    private static String subjectName_IPSEC = "CN=LTE02ERBS00002-ipsec,C=SE,O=ERICSSON,OU=BUCI DUAC NAM";
    private static String issuerName_IPSEC = "NE_IPSEC_CA";
    private static String nodeName = "LTE02ERBS00002";
    private static String subjectName_UNKNOWN = "CN=D16R227385.ericsson.com";

    @Test
    public void testBuildCertificateEnrollementStatusForOAM() {
        certificateEnrollmentStatusBuilder.build(subjectName_OAM, issuerName_OAM, CertificateEnrollmentStatusType.SUCCESS);
        assertEquals(CertificateType.OAM, certificateEnrollmentStatusBuilder.build(subjectName_OAM, issuerName_OAM, CertificateEnrollmentStatusType.SUCCESS).getCertificateType());
        assertEquals(nodeName, certificateEnrollmentStatusBuilder.build(subjectName_OAM, issuerName_OAM, CertificateEnrollmentStatusType.SUCCESS).getNodeName());
        Mockito.never();
    }

    @Test
    public void testBuildCertificateEnrollementStatusForIPSEC() {
        certificateEnrollmentStatusBuilder.build(subjectName_IPSEC, issuerName_IPSEC, CertificateEnrollmentStatusType.SUCCESS);
        assertEquals(CertificateType.IPSEC, certificateEnrollmentStatusBuilder.build(subjectName_IPSEC, issuerName_IPSEC, CertificateEnrollmentStatusType.SUCCESS).getCertificateType());
        assertEquals(nodeName, certificateEnrollmentStatusBuilder.build(subjectName_IPSEC, issuerName_IPSEC, CertificateEnrollmentStatusType.SUCCESS).getNodeName());
        Mockito.never();
    }

    @Test
    public void testBuildCertificateEnrollementStatusForUNKNOWN() {
        certificateEnrollmentStatusBuilder.build(subjectName_UNKNOWN, issuerName_OAM, CertificateEnrollmentStatusType.SUCCESS);
        assertEquals(CertificateType.UNKNOWN, certificateEnrollmentStatusBuilder.build(subjectName_UNKNOWN, issuerName_OAM, CertificateEnrollmentStatusType.SUCCESS).getCertificateType());
        assertEquals(subjectName_UNKNOWN, certificateEnrollmentStatusBuilder.build(subjectName_UNKNOWN, issuerName_OAM, CertificateEnrollmentStatusType.SUCCESS).getNodeName());
        Mockito.never();
    }

    @Test
    public void testBuildCertificateEnrollementStatusForFAILURE() {
        certificateEnrollmentStatusBuilder.build(subjectName_OAM, issuerName_OAM, CertificateEnrollmentStatusType.FAILURE);
        assertEquals(CertificateType.OAM, certificateEnrollmentStatusBuilder.build(subjectName_OAM, issuerName_OAM, CertificateEnrollmentStatusType.FAILURE).getCertificateType());
        assertEquals(nodeName, certificateEnrollmentStatusBuilder.build(subjectName_OAM, issuerName_OAM, CertificateEnrollmentStatusType.FAILURE).getNodeName());
        Mockito.never();
    }

    @Test
    public void testSplitDNs() {
        final String testSubject1 = "C=CN1,CN2,L=Genova,ST=Italy";
        final String testSubject2 = "C=CN1,CN2,O=TestO1,TestO2";

        final String expectedTestSubject1 = "[C=CN1, CN2, L=Genova, ST=Italy]";
        final String expectedTestSubject2 = "[C=CN1, CN2, O=TestO1, TestO2]";

        assertEquals(expectedTestSubject1, Arrays.toString(CertificateEnrollmentStatusBuilder.splitDNs(testSubject1)));
        assertEquals(expectedTestSubject2, Arrays.toString(CertificateEnrollmentStatusBuilder.splitDNs(testSubject2)));
    }
}
