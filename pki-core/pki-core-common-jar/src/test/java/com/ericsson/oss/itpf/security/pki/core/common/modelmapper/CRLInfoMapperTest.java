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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRL;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;

@RunWith(MockitoJUnitRunner.class)
public class CRLInfoMapperTest {

    @InjectMocks
    CRLInfoMapper crlInfoMapper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateModelMapper modelMapper;

    private CRLInfoData cRLInfoData;
    private CRLInfo crlInfo;

    @Before
    public void setUp() throws ParseException, CertificateEncodingException, CertificateException, IOException, CRLException {
        cRLInfoData = new CRLInfoData();
        crlInfo = new CRLInfo();
        cRLInfoData.setId(123);
        cRLInfoData.setCrlNumber(3214);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        cRLInfoData.setNextUpdate(sdf.parse("2019-01-01"));
        cRLInfoData.setStatus(CRLStatus.LATEST);
        CertificateData certificateData = new CertificateData();
        certificateData.setId(123);
        certificateData.setSerialNumber("321");
        certificateData.setStatus(CertificateStatus.ACTIVE);
        cRLInfoData.setCertificateData(certificateData);

        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setId(123);
        issuerCertificate.setSerialNumber("123");
        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        crlInfo.setIssuerCertificate(issuerCertificate);

        CRLNumber crlNumber = new CRLNumber();
        crlNumber.setCritical(true);
        crlNumber.setSerialNumber(123);
        crlInfo.setCrlNumber(crlNumber);
        CRL crl = new CRL();
        crl.setId(123);
        crlInfo.setCrl(crl);
    }

    @Test
    public void testFromAPIToModel() {
        CertificateData certificateData = new CertificateData();
        CRLData crlDataReturn = new CRLData();
        Mockito.when(persistenceManager.findEntity(CertificateData.class, crlInfo.getIssuerCertificate().getId())).thenReturn(certificateData);
        Mockito.when(persistenceManager.findEntity(CRLData.class, crlInfo.getCrl().getId())).thenReturn(crlDataReturn);
        CRLInfoData crlInfoDataReturn = crlInfoMapper.fromAPIToModel(crlInfo);
    }

    @Test
    public void testToAPIToModel() {
        CRLInfo crlInfo = crlInfoMapper.toAPIFromModel(cRLInfoData);

    }

    @Test(expected = CRLServiceException.class)
    public void testToAPIToModel_CRLServiceException() throws CertificateEncodingException, CertificateException, IOException {
        testToAPIToModel_setup();
        CRLInfo crlInfo = crlInfoMapper.toAPIFromModel(cRLInfoData);
    }

    private void testToAPIToModel_setup() throws CertificateEncodingException, CertificateException, IOException {
        CRLData crlData = new CRLData();
        crlData.setCrl(getX509Certificate("MyRoot.crt").getEncoded());
        crlData.setId(12345);
        cRLInfoData.setCrl(crlData);
    }

    public X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }
}
