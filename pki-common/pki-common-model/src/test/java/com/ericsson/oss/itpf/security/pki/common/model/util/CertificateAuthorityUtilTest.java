/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.common.model.util;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;

@RunWith(MockitoJUnitRunner.class)
public class CertificateAuthorityUtilTest {
    private Certificate certificate;
    private CertificateAuthority certificateAuthority;

    @InjectMocks
    CertificateAuthorityUtil certificateAuthorityUtil;

    @Before
    public void setUp() {
        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(123456);

        certificateAuthority.setName("TestingCertificate");
    }

    @Test
    public void testGetCACertificatesByStatus_CertificateStatusActive() {
        certificate = new Certificate();
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(certificate);
        List<Certificate> activeCertificates = CertificateAuthorityUtil.getCACertificatesByStatus(certificateAuthority, CertificateStatus.ACTIVE);
        assertEquals(CertificateStatus.ACTIVE, activeCertificates.get(0).getStatus());
    }

    @Test
    public void testGetCACertificatesByStatus_CertificateStatusInActive() {
        certificate = new Certificate();
        certificate.setStatus(CertificateStatus.INACTIVE);
        List<Certificate> inAtiveCertificates = new ArrayList<Certificate>();
        inAtiveCertificates.add(certificate);
        certificateAuthority.setInActiveCertificates(inAtiveCertificates);
        List<Certificate> activeCertificates = CertificateAuthorityUtil.getCACertificatesByStatus(certificateAuthority, CertificateStatus.INACTIVE);
        assertEquals(CertificateStatus.INACTIVE, activeCertificates.get(0).getStatus());
    }

    @Test
    public void testGetCACertificatesByStatus_CertificateStatusExpired() {
        certificate = new Certificate();
        certificate.setStatus(CertificateStatus.EXPIRED);
        List<Certificate> inAtiveCertificates = new ArrayList<Certificate>();
        inAtiveCertificates.add(certificate);
        certificateAuthority.setInActiveCertificates(inAtiveCertificates);
        List<Certificate> activeCertificates = CertificateAuthorityUtil.getCACertificatesByStatus(certificateAuthority, CertificateStatus.EXPIRED);
        assertEquals(CertificateStatus.EXPIRED, activeCertificates.get(0).getStatus());
    }

    @Test
    public void testGetCACertificatesByStatus_CertificateStatusRevoked() {
        certificate = new Certificate();
        certificate.setStatus(CertificateStatus.REVOKED);
        List<Certificate> inAtiveCertificates = new ArrayList<Certificate>();
        inAtiveCertificates.add(certificate);
        certificateAuthority.setInActiveCertificates(inAtiveCertificates);
        List<Certificate> activeCertificates = CertificateAuthorityUtil.getCACertificatesByStatus(certificateAuthority, CertificateStatus.REVOKED);
        assertEquals(CertificateStatus.REVOKED, activeCertificates.get(0).getStatus());
    }
}
