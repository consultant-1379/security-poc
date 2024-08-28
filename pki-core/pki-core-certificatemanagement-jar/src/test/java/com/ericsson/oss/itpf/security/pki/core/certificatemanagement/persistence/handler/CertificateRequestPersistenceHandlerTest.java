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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler;

import java.io.IOException;

import javax.persistence.EntityExistsException;
import javax.persistence.TransactionRequiredException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateRequestPersistenceHandlerTest extends BaseTest {

    @InjectMocks
    private CertificateRequestPersistenceHandler certificateRequestPersistenceHandlerBean;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private PKCS10CertificationRequest certificationRequest;

    private CertificateGenerationInfo certificateGenerationInfo;
    private CertificateGenerationInfoData certificateGenerationInfoData;
    private CertificateAuthorityData certificateAuthorityData;
    private CertificateRequestData certificateRequestData;
    private EntityInfoData entityData;
    private CertificateData certificateData;

    /**
     * Prepares initial data.
     */
    @Before
    public void setUp() {

        certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfo.setId(Long.valueOf(1));
        certificateGenerationInfoData = new CertificateGenerationInfoData();
        certificateAuthorityData = new CertificateAuthorityData();
        certificateRequestData = new CertificateRequestData();
        certificateData = new CertificateData();
    }

    /**
     * Method to test storing of {@link CertificateGenerationInfo} to the database.
     * 
     * @throws IOException
     * 
     */
    @Ignore
    @Test
    public void testStoreCertificateGenerationInfo() throws IOException {

        certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificationRequest.getEncoded(), entityData, certificateData);

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, null)).thenReturn(
                certificateGenerationInfoData);

        Mockito.doNothing().when(persistenceManager).createEntity(certificateGenerationInfoData);

        certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, null, certificateData);

        Mockito.verify(persistenceManager).createEntity(certificateGenerationInfoData);

    }

    /**
     * Method to test storing of {@link CertificateGenerationInfo} to the database.
     * 
     * @throws IOException
     * 
     */
    @Test
    public void testStoreCertificateGenerationInfoWithCertificateAuthority() throws IOException {

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, entityData)).thenReturn(
                certificateGenerationInfoData);

        Mockito.doNothing().when(persistenceManager).createEntity(certificateGenerationInfoData);

        certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, entityData, certificateData);

        Mockito.verify(persistenceManager).createEntity(certificateGenerationInfoData);
    }

    /**
     * Method to test update of {@link CSR} status to failed in database.
     */
    @Test
    public void testupdateCertificateRequestStatus() {

        Mockito.when(persistenceManager.updateEntity(certificateRequestData)).thenReturn(certificateRequestData);
        certificateRequestPersistenceHandlerBean.updateCertificateRequestStatus(certificateRequestData);

        Mockito.verify(persistenceManager).updateEntity(certificateRequestData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testupdateCertificateRequestStatus_CertificateServiceException() {

        Mockito.when(persistenceManager.updateEntity(certificateRequestData)).thenThrow(new TransactionRequiredException());
        certificateRequestPersistenceHandlerBean.updateCertificateRequestStatus(certificateRequestData);

    }

    @Test(expected = CertificateGenerationException.class)
    public void testStoreCertificateGenerationInfoWithCertificateAuthority_CertificateRequestGenerationException() throws IOException {

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, null)).thenReturn(
                certificateGenerationInfoData);

        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(certificateGenerationInfoData);

        certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, entityData, certificateData);

    }

    @Test(expected = CertificateServiceException.class)
    public void testStoreCertificateGenerationInfoWithCertificateAuthority_CertificateServiceException() throws IOException {

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, null)).thenReturn(
                certificateGenerationInfoData);

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(certificateGenerationInfoData);

        certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificationRequest.getEncoded(), certificateAuthorityData, entityData, certificateData);

    }
}
