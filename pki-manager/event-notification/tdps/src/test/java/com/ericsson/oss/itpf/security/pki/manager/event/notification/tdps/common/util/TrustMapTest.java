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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.util;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.util.TrustMap;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

@RunWith(MockitoJUnitRunner.class)
public class TrustMapTest {

    @InjectMocks
    TrustMap trustMap;

    @Mock
    Certificate certificate;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    CertificateAuthority certificateAuthority;

    private static TDPSEntityType tdpsEntityType;
    private static Map<String, List<Certificate>> allTrusts;

    @Test
    public void testGet() throws CertificateEncodingException {
        setupData();

        tdpsEntityType = TDPSEntityType.ENTITY;

        Mockito.when(certificate.getStatus()).thenReturn(CertificateStatus.ACTIVE);

        List<TDPSCertificateInfo> tdpsCertificateInfoList = TrustMap.get(tdpsEntityType, allTrusts);

        Assert.assertEquals("key", tdpsCertificateInfoList.get(0).getEntityName());

    }

    @Test
    public void testGetInActive() throws CertificateEncodingException {
        setupData();

        tdpsEntityType = TDPSEntityType.ENTITY;

        Mockito.when(certificate.getStatus()).thenReturn(CertificateStatus.INACTIVE);

        List<TDPSCertificateInfo> tdpsCertificateInfoList = TrustMap.get(tdpsEntityType, allTrusts);

        Assert.assertEquals("key", tdpsCertificateInfoList.get(0).getEntityName());
    }

    @Test
    public void testGetInUnknown() throws CertificateEncodingException {
        setupData();

        tdpsEntityType = TDPSEntityType.ENTITY;

        Mockito.when(certificate.getStatus()).thenReturn(CertificateStatus.EXPIRED);

        List<TDPSCertificateInfo> tdpsCertificateInfoList = TrustMap.get(tdpsEntityType, allTrusts);
        Assert.assertEquals("key", tdpsCertificateInfoList.get(0).getEntityName());
    }

    @Test
    public void getCertificateNull() throws CertificateEncodingException {

        setupData();

        tdpsEntityType = TDPSEntityType.ENTITY;

        allTrusts.clear();
        final List<Certificate> listCertificate = new ArrayList<Certificate>();
        listCertificate.add(null);
        allTrusts.put("key", listCertificate);
        List<TDPSCertificateInfo> tdpsCertificateInfoList = TrustMap.get(tdpsEntityType, allTrusts);
        Assert.assertEquals(0, tdpsCertificateInfoList.size());

    }

    @Test
    public void testGetInUnknownCertificateEncodingExc() throws CertificateEncodingException {
        setupData();

        tdpsEntityType = TDPSEntityType.ENTITY;

        Mockito.when(certificate.getStatus()).thenReturn(CertificateStatus.EXPIRED);

        Mockito.when(certificate.getX509Certificate().getEncoded()).thenThrow(new CertificateEncodingException());

        List<TDPSCertificateInfo> tdpsCertificateInfoList = TrustMap.get(tdpsEntityType, allTrusts);

        Assert.assertEquals(0, tdpsCertificateInfoList.size());
    }

    public void setupData() throws CertificateEncodingException {
        final byte[] encoded = new byte[] { 1 };
        final String authorityName = "authorityName";
        final String serialNumber = "1";

        Mockito.when(certificate.getX509Certificate()).thenReturn(x509Certificate);

        Mockito.when(certificate.getX509Certificate().getEncoded()).thenReturn(encoded);
        Mockito.when(certificate.getSerialNumber()).thenReturn(serialNumber);
        Mockito.when(certificate.getIssuer()).thenReturn(certificateAuthority);
        Mockito.when(certificate.getIssuer().getName()).thenReturn(authorityName);

        List<Certificate> listCertificate = new ArrayList<Certificate>();
        listCertificate.add(certificate);
        allTrusts = new HashMap<String, List<Certificate>>();
        allTrusts.put("key", listCertificate);

    }

}
