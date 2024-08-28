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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRL;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;

import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ExtCAManagementService;

/**
 * 
 * Junit Tests for ExternalCACRLHandler.
 * 
 * @author tcsviku
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class ExternalCACRLHandlerTest {

    @InjectMocks
    ExternalCACRLHandler externalCACRLHandler;

    @Mock
    private Logger logger;

    @Mock
    ExtCAManagementService extCAManagementService;

    @Mock
    ExtCACRLManager extCACRLManager;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CRLHelper crlHelper;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    ExternalCRLMapper externalCRLMapper;

    private static List<CertificateData> certifiates = new ArrayList<CertificateData>();
    final static String EXTCANAME = "External_CA";
    final ExternalCRLInfo externalCRLInfo = new ExternalCRLInfo();
    final CertificateData certificate = new CertificateData();
    final CertificateAuthority certificateAuthority = new CertificateAuthority();
    private final String SERIAL_NUMBER = "31da3380182af9b2";
    private final String END_OF_EXTERNAL_CRL_HANDLER = "End of externalCACRLHandle method in ExternalCACRLHandler class";
    private final String EXPIRED_CRL = "CRL for ExternalCA {} is expired";

    private CAEntityData issuerCA = new CAEntityData();

    private CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

    private ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();

    private X509CRL x509Crl = null;
    private static String cdpsUrl = "http://www.enmpki.co/enmCA.pem";
    private static String updateURL = "http://www.enmpki.co/pkiCA.pem";
    private static String crlFilePath = "crls/testCA.crl";

    /**
     * 
     * Prepares initial Data.
     * 
     * @throws Exception
     */
    @Before
    public void setUpData() throws Exception {

        certificateAuthority.setName(EXTCANAME);
        final CRL crl = new CRL();
        crl.setId(123456);

        x509Crl = getX509CRL(crlFilePath);
        final X509CRLHolder x509crlHolder = new X509CRLHolder(x509Crl);
        crl.setX509CRLHolder(x509crlHolder);
        externalCrlInfoData.setId(5);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        issuerCA.setCertificateAuthorityData(certificateAuthorityData);
        certificate.setId(1);
        certificate.setSerialNumber(SERIAL_NUMBER);
        certificate.setIssuerCA(issuerCA);
        certifiates.add(certificate);
        externalCRLInfo.setId(1);
        externalCRLInfo.setUpdateURL(updateURL);
        externalCRLInfo.setX509CRL(x509crlHolder);

    }

	/**
     * 
     * Method to test externalCACRLHandle with Valid CRL.
     * 
     */
    @Test
    public void testExternalCACRLHandle_ValidCrl() {

        when(certificatePersistenceHelper.getCertificatesIssuedByExternalCA()).thenReturn(certifiates);
        when(externalCRLMapper.toAPIFromModel(certificate.getIssuerCA().getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(externalCRLInfo);
        try {
            when(crlHelper.getCRLFromExternalCDPS(externalCRLInfo.getUpdateURL())).thenReturn(x509Crl);
        } catch (CRLNotFoundException | CertificateException | CRLException | IOException e) {
            e.printStackTrace();
        }
        externalCACRLHandler.externalCACRLHandle();

        verify(logger).debug(END_OF_EXTERNAL_CRL_HANDLER);

    }

    /**
     * 
     * Method to test externalCACRLHandle when CRL is Expired.
     * 
     */
    @Test
    public void testExternalCACRLHandle_CrlExpired() {

        try {
            x509Crl = getX509CRL(crlFilePath);

            when(certificatePersistenceHelper.getCertificatesIssuedByExternalCA()).thenReturn(certifiates);
            when(externalCRLMapper.toAPIFromModel(certificate.getIssuerCA().getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(externalCRLInfo);
            when(crlHelper.getCRLFromExternalCDPS(externalCRLInfo.getUpdateURL())).thenReturn(x509Crl);
        } catch (CRLNotFoundException | CertificateException | CRLException | IOException e) {
            e.printStackTrace();
        }
        externalCACRLHandler.externalCACRLHandle();
        verify(logger).debug(EXPIRED_CRL, certificate.getIssuerCA().getCertificateAuthorityData().getName());
        verify(logger).debug(END_OF_EXTERNAL_CRL_HANDLER);

    }

    /**
     * 
     * Method to test externalCACRLHandle if any Exception occurs.
     *
     */
    @Test(expected = Exception.class)
    public void testExternalCACRLHandle_Exception() {
        when(certificatePersistenceHelper.getCertificatesIssuedByExternalCA()).thenReturn(certifiates);
        when(externalCRLMapper.toAPIFromModel(certificate.getIssuerCA().getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(externalCRLInfo);
        try {
            Mockito.doThrow(Exception.class).when(crlHelper).getCRLFromExternalCDPS(cdpsUrl);
        } catch (CRLNotFoundException | CertificateException | CRLException | IOException e) {
            e.printStackTrace();
        }
        externalCACRLHandler.externalCACRLHandle();
    }

    private X509CRL getX509CRL(final String fileName) throws FileNotFoundException, CRLException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        return x509crl;
    }

}
