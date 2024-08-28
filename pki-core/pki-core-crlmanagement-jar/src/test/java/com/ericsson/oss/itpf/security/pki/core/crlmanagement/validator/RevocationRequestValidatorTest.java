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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.validator;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.util.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class RevocationRequestValidatorTest extends BaseTest {

    @InjectMocks
    RevocationRequestValidator revocationRequestValidator;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateData certificateData;

    @Mock
    private SystemRecorder systemRecorder;

    private static RevocationRequestData revocationRequestDataForCaEntity;
    private static RevocationRequestData revocationRequestDataForEntity;
    private static CertificateAuthorityData certificateAuthorityData;
    private static EntityInfoData entityInfoData;
    private static CertificateData issuerCertificateData;
    private static Set<CertificateData> certificateDatas = new HashSet<CertificateData>();

    @Before
    public void setUp() {
        revocationRequestDataForCaEntity = new RevocationRequestData();
        revocationRequestDataForEntity = new RevocationRequestData();

        certificateAuthorityData = prepareCertificateAuthorityData(101, "ENMSUBCA");
        entityInfoData = prepareEntityInfoData(1001, "Entity1");

        certificateData = prepareCertificateData(111, "1001");
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateDatas.clear();
        certificateDatas.add(certificateData);

        issuerCertificateData = prepareCertificateData(555, "ENMROOTCA");
        issuerCertificateData.setStatus(CertificateStatus.ACTIVE);
        certificateData.setIssuerCertificate(issuerCertificateData);

        revocationRequestDataForCaEntity.setEntity(null);
        revocationRequestDataForCaEntity.setCaEntity(certificateAuthorityData);
        revocationRequestDataForCaEntity.getCertificatesToRevoke().add(certificateData);
        certificateAuthorityData.setCertificateDatas(certificateDatas);

        revocationRequestDataForEntity.setEntity(null);
        revocationRequestDataForEntity.setEntity(entityInfoData);
        revocationRequestDataForEntity.getCertificatesToRevoke().add(certificateData);
        entityInfoData.setCertificateDatas(certificateDatas);

    }

    /**
     * This method will validate the {@link RevocationRequestData} for {@link CertificateAuthorityData}
     * 
     */
    @Test
    public void testValidateCaEntity() {
        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getIssuerCertificate().getId())).thenReturn(issuerCertificateData);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * This method will validate the {@link RevocationRequestData} for {@link EntityInfoData}
     * 
     */
    @Test
    public void testValidateEntity() {
        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getIssuerCertificate().getId())).thenReturn(issuerCertificateData);
        revocationRequestValidator.validate(revocationRequestDataForEntity);
    }

    /**
     * This method will test the {@link EntityNotFoundException} when caentity and entity is not found
     * 
     */
    @Test(expected = CoreEntityNotFoundException.class)
    public void testValidate_EntityNotFoundException() {
        revocationRequestDataForCaEntity.setCaEntity(null);
        revocationRequestDataForCaEntity.setEntity(null);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * This method will test {@link RootCertificateRevocationException} when revocation request is for Root CA
     * 
     */
    @Test(expected = RootCARevocationException.class)
    public void testValidate_RootCertificateRevocationException() {
        certificateAuthorityData.setRootCA(true);
        revocationRequestDataForCaEntity.setCaEntity(certificateAuthorityData);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * This method will test {@link CertificateNotFoundException} when certificate is not found
     * 
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testValidate_CertificateNotFoundException() {
        revocationRequestDataForCaEntity.setCertificatesToRevoke(null);
        ;
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * this method will {@link ExpiredCertificateException} when certificate status is expired
     * 
     */
    @Test(expected = CertificateExpiredException.class)
    public void testValidate_ExpiredCertificateException() {
        certificateData.setStatus(CertificateStatus.EXPIRED);
        revocationRequestDataForCaEntity.getCertificatesToRevoke().add(certificateData);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * this method will test the {@link RevocationServiceException} when internal exception is raised
     * 
     */
    @Test
    public void testValidate_RevocationServiceException() {
        Mockito.doThrow(new PersistenceException(ErrorMessages.INTERNAL_ERROR)).when(persistenceManager).findEntity(CertificateData.class, certificateData.getIssuerCertificate().getId());
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * this method will test {@link RevokedCertificateException} when certificate is revoked for an entity
     * 
     */
    @Test(expected = CertificateRevokedException.class)
    public void testValidate_RevokedCertificateException() {
        certificateData.setStatus(CertificateStatus.REVOKED);
        revocationRequestDataForCaEntity.getCertificatesToRevoke().add(certificateData);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * this method will test {@link IssuerCertificateRevokedException} when issuer certificate is revoked for an entity
     * 
     */
    @Test(expected = CertificatePathValidationException.class)
    public void testValidate_IssuerCertificateRevokedException() {
        issuerCertificateData.setStatus(CertificateStatus.REVOKED);
        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getIssuerCertificate().getId())).thenReturn(issuerCertificateData);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * This method will test {@link DataOutOfSyncException} when certificate data in revocation request and in CAentity is not matched
     * 
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testValidateCaentity_DataOutOfSyncException() {
        certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(prepareCertificateData(111, "10011"));
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        revocationRequestDataForCaEntity.setCaEntity(certificateAuthorityData);
        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getIssuerCertificate().getId())).thenReturn(issuerCertificateData);
        revocationRequestValidator.validate(revocationRequestDataForCaEntity);
    }

    /**
     * This method will test {@link DataOutOfSyncException} when certificate data in revocation request and in entity is not matched
     * 
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testValidateEntity_DataOutOfSyncException() {
        certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(prepareCertificateData(111, "10011"));
        entityInfoData.setCertificateDatas(certificateDatas);
        revocationRequestDataForEntity.setEntity(entityInfoData);
        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getIssuerCertificate().getId())).thenReturn(issuerCertificateData);
        revocationRequestValidator.validate(revocationRequestDataForEntity);
    }
}
