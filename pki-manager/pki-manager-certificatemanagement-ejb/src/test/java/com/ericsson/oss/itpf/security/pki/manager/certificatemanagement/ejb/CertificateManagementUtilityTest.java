/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.utility.CertificateManagementUtility;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementUtilityTest {

    @InjectMocks
    CertificateManagementUtility certificateManagementUtility;

    @Mock
    Logger logger;

    private static SetUPData setupData;
    private static X509Certificate x509Certificate = null;
    private static Certificate certificate = null;
    static List<Certificate> certificateList = new ArrayList<>();

    @BeforeClass
    public static void setup() {
        setupData = new SetUPData();
        try {
            certificate = setupData.getCertificate("certificates/ENMRootCA.crt");
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }
        x509Certificate = certificate.getX509Certificate();
        certificateList.add(certificate);
    }

    @Test
    public void testRemoveExpiredCertificatesIfRequired() {
        certificateManagementUtility.removeExpiredCertificates(certificateList);
    }

    @Test
    public void testRemoveExpiredCertificatesWithRevokedStatus() {
        certificateManagementUtility.removeExpiredCertificates(certificateList);
    }
}
