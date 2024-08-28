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
package com.ericsson.oss.itpf.security.pki.manager.common.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.util.Calendar;


import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl.CRLPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

@RunWith(MockitoJUnitRunner.class)
public class CRLHelperTest {

    @InjectMocks
    CRLHelper crlHelper;

    @Mock
    private CRLPersistenceHandler crlPersistenceHandler;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    private CACertificateIdentifier caCertificateIdentifier;
    private CAEntity caEntity;
    private CertificateAuthority certificateAuthority;
    private CRLInfo crlInfo;
    private List<CRLInfo> crlInfos;
    private static final String CERTIFICATE_DATE = "01-11-2040";

    @Before
    public void setUp() {
        caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("TestingCertificate");
        caCertificateIdentifier.setCerficateSerialNumber("123456");

        caEntity = new CAEntity();
        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(123456);
        certificateAuthority.setName("TestingCertificate");
        caEntity.setCertificateAuthority(certificateAuthority);
        crlInfo = new CRLInfo();
        crlInfo.setId(987456);
        crlInfo.setStatus(CRLStatus.LATEST);
        final Certificate issuerCertificate = new Certificate();
        issuerCertificate.setId(123456);
        issuerCertificate.setSerialNumber("123456");
        crlInfo.setIssuerCertificate(issuerCertificate);
        crlInfos = new ArrayList<CRLInfo>();
        crlInfos.add(crlInfo);
        certificateAuthority.setCrlInfo(crlInfos);
    }

    @Test
    public void testGetCRLByCACertificate() throws ParseException {
        certificateAuthority.setStatus(CAStatus.ACTIVE);
        final Certificate activeCertificate = new Certificate();
        activeCertificate.setId(123456);
        activeCertificate.setSerialNumber("123456");

        final Date inputDate = getDate();
        activeCertificate.setNotBefore(inputDate);
        activeCertificate.setNotAfter(inputDate);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setInActiveCertificates(null);
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);

        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());
    }

    @Test
    public void testGetCRLByCACertificate_CAStatus_INACTIVE() throws ParseException {
        final List<Certificate> inActiveCertificates = new ArrayList<Certificate>();
        final Certificate certificate = new Certificate();
        certificate.setId(123456);
        certificate.setSerialNumber("123456");

        final Date inputDate = getDate();
        certificate.setNotBefore(inputDate);
        certificate.setNotAfter(inputDate);
        certificate.setStatus(CertificateStatus.INACTIVE);
        inActiveCertificates.add(certificate);
        certificateAuthority.setInActiveCertificates(inActiveCertificates);
        certificateAuthority.setActiveCertificate(null);
        certificateAuthority.setStatus(CAStatus.INACTIVE);

        certificateAuthority.setCrlInfo(crlInfos);
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);

        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCRLByCACertificate_CertificateNotFoundException() throws ParseException {
        final List<Certificate> inActiveCertificates = new ArrayList<Certificate>();
        final Certificate certificate = new Certificate();
        certificate.setId(1236);
        certificate.setSerialNumber("1236");

        final Date inputDate = getDate();
        certificate.setNotBefore(inputDate);
        certificate.setNotAfter(inputDate);
        certificate.setStatus(CertificateStatus.INACTIVE);
        inActiveCertificates.add(certificate);
        certificateAuthority.setInActiveCertificates(inActiveCertificates);
        certificateAuthority.setStatus(CAStatus.INACTIVE);
        certificateAuthority.setCrlInfo(crlInfos);
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);
        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());

    }

    @Test(expected = CRLNotFoundException.class)
    public void testGetCRLByCACertificate_CRLNotFoundException_With_CRLInfoList_Empty() throws ParseException {
        certificateAuthority.setStatus(CAStatus.ACTIVE);
        final Certificate activeCertificate = new Certificate();
        activeCertificate.setId(123456);
        activeCertificate.setSerialNumber("123456");

        final Date inputDate = getDate();
        activeCertificate.setNotBefore(inputDate);
        activeCertificate.setNotAfter(inputDate);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setInActiveCertificates(null);
        certificateAuthority.setCrlInfo(new ArrayList<CRLInfo>());
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);

        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());
    }

    @Test(expected = CRLNotFoundException.class)
    public void testGetCRLByCACertificate_CRLNotFoundException() throws ParseException {

        certificateAuthority.setStatus(CAStatus.ACTIVE);
        final Certificate activeCertificate = new Certificate();
        activeCertificate.setId(123456);
        activeCertificate.setSerialNumber("123456");

        final Date inputDate = getDate();
        activeCertificate.setNotBefore(inputDate);
        activeCertificate.setNotAfter(inputDate);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setInActiveCertificates(null);
        crlInfo = new CRLInfo();
        crlInfo.setId(987456);
        crlInfo.setStatus(CRLStatus.LATEST);
        final Certificate issuerCertificate = new Certificate();
        issuerCertificate.setId(12356);
        issuerCertificate.setSerialNumber("12456");
        crlInfo.setIssuerCertificate(issuerCertificate);
        crlInfos = new ArrayList<CRLInfo>();
        crlInfos.add(crlInfo);
        certificateAuthority.setCrlInfo(crlInfos);
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);

        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());
    }

    @Test(expected = RevokedCertificateException.class)
    public void testGetCRLByCACertificate_RevokedCertificateException() throws ParseException {

        certificateAuthority.setStatus(CAStatus.ACTIVE);
        final Certificate activeCertificate = new Certificate();
        activeCertificate.setId(123456);
        activeCertificate.setSerialNumber("123456");

        final Date inputDate = getDate();
        activeCertificate.setNotBefore(inputDate);
        activeCertificate.setNotAfter(inputDate);
        activeCertificate.setStatus(CertificateStatus.REVOKED);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setInActiveCertificates(null);
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);

        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());
    }

    @Test(expected = ExpiredCertificateException.class)
    public void testGetCRLByCACertificate_ExpiredCertificateException() throws ParseException {

        certificateAuthority.setStatus(CAStatus.ACTIVE);
        final Certificate activeCertificate = new Certificate();
        activeCertificate.setId(123456);
        activeCertificate.setSerialNumber("123456");
        final String inputStr = "1-11-2015";
        final DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");
        final Date inputDate = dateFormat.parse(inputStr);
        activeCertificate.setNotBefore(inputDate);
        activeCertificate.setNotAfter(inputDate);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setInActiveCertificates(null);
        Mockito.when(crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName())).thenReturn(caEntity);

        final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);

        Mockito.verify(crlPersistenceHandler, times(1)).getCAEntity(caCertificateIdentifier.getCaName());
        assertNotNull(crlInfo);
        assertNotNull(crlInfo.getId());
        assertNotNull(crlInfo.getStatus());
    }

    @Test
    public void testUpdateCRLStatus() {
        crlHelper.updateCRLStatus(crlInfo);
        Mockito.verify(logger, times(1)).debug("updateCRLStatus method in CRLHelper class using CRLInfo object");
    }

    @Test
    public void testGetAllCRLsWithLatestStatus() {

        Mockito.when(crlPersistenceHandler.getCRLInfoByStatus(CRLStatus.LATEST)).thenReturn(crlInfos);

        final List<CRLInfo> crlInfoList = crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST);

        assertNotNull(crlInfoList);
        assertEquals(987456, crlInfoList.get(0).getId());
        assertEquals(CRLStatus.LATEST, crlInfoList.get(0).getStatus());

    }

    @Test
    public void testGetCANameByCRL() {

        final String caName = "TESTCA";
        Mockito.when(crlPersistenceHandler.getCANameByCRL(crlInfo.getId())).thenReturn(caName);

        final String caNameReturn = crlHelper.getCANameByCRL(crlInfo.getId());

        assertNotNull(caNameReturn);
        assertEquals(caName, caNameReturn);
    }

    @Test
    public void testIsCRLExists() {
        final Certificate certificate = new Certificate();
        certificate.setId(123456);
        certificate.setSerialNumber("123456");
        final boolean crlExistsFlag = crlHelper.isCRLExists(crlInfos, certificate);
        assertTrue(crlExistsFlag);

    }

    @Test(expected = CRLNotFoundException.class)
    public void testGetCRLFromExternalCDPS_CRLNotFoundException() throws CRLNotFoundException, CertificateException, CRLException,
            MalformedURLException, IOException {
        final X509CRL x509Crl = crlHelper.getCRLFromExternalCDPS("htt://www.Example.com");
        assertNotNull(x509Crl);
    }

    private Date getDate() {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        return c.getTime();
    }
}
