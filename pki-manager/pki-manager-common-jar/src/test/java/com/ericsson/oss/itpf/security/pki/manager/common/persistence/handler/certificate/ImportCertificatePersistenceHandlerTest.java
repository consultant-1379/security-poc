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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class ImportCertificatePersistenceHandlerTest {

    @InjectMocks
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Mock
    Query query;

    @Mock
    Logger logger;

    private CAEntityData caEntityData;
    private CertificateAuthorityData certificateAuthorityData;
    private X509Certificate x509Certificate;
    private CertificateData certData;
    List<CertificateData> certDataList;

    private SetUPData setUPData;

    @Before
    public void setUp() throws CertificateException, IOException, java.security.cert.CertificateException {

        setUPData = new SetUPData();
        caEntityData = new CAEntityData();
        certificateAuthorityData = new CertificateAuthorityData();
        certData = new CertificateData();
        certDataList = new ArrayList<>();

        certDataList.add(certData);

        x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");

        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
    }

    @Test
    public void testStoreCertificate() throws CANotFoundException, PersistenceException, CertificateServiceException, EntityServiceException, InvalidOperationException,
            java.security.cert.CertificateException {
        Mockito.when(caCertificatePersistenceHelper.getCAEntity("caName")).thenReturn(caEntityData);

        importCertificatePersistenceHandler.storeCertificate("caName", x509Certificate);
    }

    @Test
    public void testUpdateIssuerCAandCertificate() {

        Mockito.when(extCACertificatePersistanceHandler.getIssuerCertificateData(x509Certificate)).thenReturn(certData);
        Mockito.when(extCACertificatePersistanceHandler.getCAEntityData(certData.getId())).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificateDatas("caName", CertificateStatus.ACTIVE)).thenReturn(certDataList);

        Mockito.doNothing().when(caCertificatePersistenceHelper).updateIssuerCAandCertificate(certData, caEntityData, certData);
        importCertificatePersistenceHandler.updateIssuerCAandCertificate("caName", x509Certificate);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testUpdateIssuerCAandCertificateWithNoCertData() {

        Mockito.when(extCACertificatePersistanceHandler.getIssuerCertificateData(x509Certificate)).thenReturn(null);

        importCertificatePersistenceHandler.updateIssuerCAandCertificate("caName", x509Certificate);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testUpdateIssuerCAandCertificateWithNoCAEntity() {

        Mockito.when(extCACertificatePersistanceHandler.getIssuerCertificateData(x509Certificate)).thenReturn(certData);
        Mockito.when(extCACertificatePersistanceHandler.getCAEntityData(certData.getId())).thenReturn(null);

        importCertificatePersistenceHandler.updateIssuerCAandCertificate("caName", x509Certificate);
    }
}
