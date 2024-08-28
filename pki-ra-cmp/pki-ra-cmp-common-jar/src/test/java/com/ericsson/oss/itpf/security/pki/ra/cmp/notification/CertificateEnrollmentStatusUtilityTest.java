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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateEnrollmentStatusUtilityTest {

    @InjectMocks
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    @Mock
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Mock
    CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Test
    public void testDispatchCertificateEnrollmentStatus_Failure() {
        String subjectName = "LTE54ERBS00001";
        String issuerName = "NE_OAM_CA";
        String errorInfo = "errorInfo";
        certificateEnrollmentStatusUtility.buildAndDispatchCertificateEnrollmentStatus(subjectName, issuerName, errorInfo);
        Mockito.verify(certificateEnrollmentStatusBuilder).build(subjectName, issuerName, CertificateEnrollmentStatusType.FAILURE);
    }

    @Test
    public void testDispatchCertificateEnrollmentStatus_CertificateSent() {
        String subjectName = "LTE54ERBS00001";
        String issuerName = "NE_OAM_CA";
        String errorInfo = "No error information";
        certificateEnrollmentStatusUtility.buildAndDispatchCertificateEnrollmentStatus(subjectName, issuerName, errorInfo);
        Mockito.verify(certificateEnrollmentStatusBuilder).build(subjectName, issuerName, CertificateEnrollmentStatusType.CERTIFICATE_SENT);
    }
}
