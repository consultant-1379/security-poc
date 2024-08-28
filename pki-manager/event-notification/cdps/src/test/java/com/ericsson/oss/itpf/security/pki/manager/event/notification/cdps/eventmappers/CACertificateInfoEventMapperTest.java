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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;

@RunWith(MockitoJUnitRunner.class)
public class CACertificateInfoEventMapperTest {

    @InjectMocks
    CACertificateInfoEventMapper caCertificateInfoEventMapper;

    private List<CACertificateInfo> caCertificateInfos;
    private CACertificateInfo caCertificateInfo;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        caCertificateInfos = new ArrayList<CACertificateInfo>();
        caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestingCACerftificate");
        caCertificateInfo.setCertificateSerialNumber("123456");
        caCertificateInfos.add(caCertificateInfo);
    }

    @Test
    public void toModel() {
        List<CACertificateIdentifier> returnListOfCertificate = caCertificateInfoEventMapper.toModel(caCertificateInfos);
        for (CACertificateIdentifier certificateIdentifier : returnListOfCertificate) {
            Assert.assertNotNull(certificateIdentifier.getCaName());
            Assert.assertNotNull(certificateIdentifier.getCerficateSerialNumber());
        }
    }

    @Test
    public void toModel_With_SingleCertificate() {
        CACertificateIdentifier caCertificateIdentifier = caCertificateInfoEventMapper.toModel(caCertificateInfo);
        Assert.assertNotNull(caCertificateIdentifier.getCaName());
        Assert.assertNotNull(caCertificateIdentifier.getCerficateSerialNumber());
    }

    @Test
    public void fromModel_With_SingleCertificate() {
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("TestingCACerftificate");
        caCertificateIdentifier.setCerficateSerialNumber("123456");
        CACertificateInfo caCertificateInfo = caCertificateInfoEventMapper.fromModel(caCertificateIdentifier);
        Assert.assertNotNull(caCertificateInfo.getCaName());
        Assert.assertNotNull(caCertificateInfo.getCertificateSerialNumber());
    }

    @Test
    public void fromModel() {
        List<CACertificateIdentifier> certificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("TestingCACerftificate");
        caCertificateIdentifier.setCerficateSerialNumber("123456");
        certificateIdentifiers.add(caCertificateIdentifier);

        List<CACertificateInfo> caCertificateInfos = caCertificateInfoEventMapper.fromModel(certificateIdentifiers);
        for (CACertificateInfo certificateInfo : caCertificateInfos) {
            Assert.assertNotNull(certificateInfo.getCaName());
            Assert.assertNotNull(certificateInfo.getCertificateSerialNumber());
        }
    }
}
