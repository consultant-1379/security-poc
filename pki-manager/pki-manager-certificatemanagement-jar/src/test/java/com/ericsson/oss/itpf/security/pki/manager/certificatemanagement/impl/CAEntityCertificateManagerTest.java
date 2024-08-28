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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.INTERNAL_ERROR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceException;
import javax.persistence.Query;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.EntitySetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.CARekeyHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.CARenewHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.GenerateCSRHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.ImportCertificateHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.InitialCACertGenerationHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateChainHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier.CertificateEventNotifier;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RootCertificateRevocationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Test class for {{@link #CAEntityCertificateManager}
 */
@RunWith(MockitoJUnitRunner.class)
public class CAEntityCertificateManagerTest {

    @InjectMocks
    CAEntityCertificateManager cAEntityCertificateManager;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    CertificateValidator certificateValidator;

    @Mock
    Logger logger;

    @Mock
    CertificateChainHelper certificateChainHelper;

    @Mock
    InitialCACertGenerationHandler initialCertGenerationHandler;

    @Mock
    CARenewHandler renewHandler;

    @Mock
    CARekeyHandler rekeyHandler;

    @Mock
    EntityHelper entityHelper;

    @Mock
    ImportCertificateHandler importCertificateHandler;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    CAEntity caEntity;

    @Mock
    RevocationManager revocationManager;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CertificateAuthority certificateAuthority;

    @Mock
    TDPSPersistenceHandler tdpsPersistenceHandler;

    @Mock
    CertificateEventNotifier certificateEventNotifier;

    @Mock
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    GenerateCSRHandler generateCSRHandler;

    @Mock
    PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;

    @Mock
    CACertificateIdentifier caCertificateIdentifier;

    @Mock
    CertificateHelper certificateHelper;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    ExtCertificateModelMapper extCertificateModelMapper;

    @Mock
    DNBasedCertificateIdentifier dNBasedIdentifier;

    Certificate certificate;

    private static SetUPData setUPData;

    private static EntitySetUPData entitySetUPData;

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @BeforeClass
    public static void setUP() {

        setUPData = new SetUPData();
        entitySetUPData = new EntitySetUPData();
    }

    /**
     * Test case for Verifying the creation of CA certificate.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCertificate() throws Exception {

        certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");

        Mockito.when(initialCertGenerationHandler.generateCertificate(SetUPData.ROOT_CA_NAME)).thenReturn(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenReturn(Arrays.asList(certificate));

        final Certificate generatedCertificate = cAEntityCertificateManager.generateCertificate(SetUPData.ROOT_CA_NAME);

        assertCertificate(generatedCertificate);
    }

    /**
     * Test case for Verifying renewal of CA certificate.
     *
     * @throws Exception
     */
    @Test
    public void testRenewCertificate() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        final CAEntityData caEntityData = getCAEntityData();

        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(caEntity);

        Mockito.doNothing().when(renewHandler).renewCertificate(caEntity, ReIssueType.CA);

        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(caEntityData);

        cAEntityCertificateManager.renewCertificate(SetUPData.ROOT_CA_NAME, ReIssueType.CA);

        Mockito.verify(entityHelper).getCAEntity(SetUPData.ROOT_CA_NAME);

        Mockito.verify(renewHandler).renewCertificate(caEntity, ReIssueType.CA);
    }

    @Test(expected = EntityNotFoundException.class)
    public void testRenewCertificate_EntityNotFoundException() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenThrow(new EntityNotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND));
        Mockito.doNothing().when(renewHandler).renewCertificate(caEntity, ReIssueType.CA);

        cAEntityCertificateManager.renewCertificate(SetUPData.ROOT_CA_NAME, ReIssueType.CA);

    }

    /**
     * Test case for Verifying renewal of CA certificate.
     * 
     * @throws Exception
     */
    @Test
    public void testRekeyCertificate() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        final CAEntityData caEntityData = getCAEntityData();

        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(caEntityData);

        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(caEntity);

        Mockito.doNothing().when(rekeyHandler).rekeyCertificate(caEntity, ReIssueType.CA);

        cAEntityCertificateManager.rekeyCertificate(SetUPData.ROOT_CA_NAME, ReIssueType.CA);

        Mockito.verify(entityHelper).getCAEntity(SetUPData.ROOT_CA_NAME);

        Mockito.verify(rekeyHandler).rekeyCertificate(caEntity, ReIssueType.CA);
    }

    @Test(expected = CANotFoundException.class)
    public void testRekeyCertificate_EntityNotFoundException() throws Exception {

        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenThrow(new EntityNotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND));
        cAEntityCertificateManager.rekeyCertificate(SetUPData.ROOT_CA_NAME, ReIssueType.CA);
    }

    /**
     * Test case for listing RootCA certificates
     *
     * @throws Exception
     */
    @Test
    public void testListCertificates_Normal() throws Exception {

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenReturn(certificates);
        final List<Certificate> returnedCertificates = cAEntityCertificateManager.listCertificates(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);

        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), certificates.size());

    }

    /**
     * Test case for checking CertificateNotFoundException is thrown when RootCA does not contain ACTIVE certificate.
     *
     * @throws Exception
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testListCertificates_No_Certificates_Found() throws Exception {

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenReturn(null);

        cAEntityCertificateManager.listCertificates(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);
    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while encoding the certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testListCertificates_IOException() throws Exception {

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenThrow(new IOException(INTERNAL_ERROR));

        cAEntityCertificateManager.listCertificates(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);
    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while retrieving the certificates from database.
     *
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testListCertificates_DataException() throws Exception {

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenThrow(new PersistenceException(INTERNAL_ERROR));

        cAEntityCertificateManager.listCertificates(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);
    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while retrieving the certificates from database.
     *
     * @throws Exception
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testListCertificates_CertificateException() throws Exception {

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenThrow(new CertificateException(INTERNAL_ERROR));

        cAEntityCertificateManager.listCertificates(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE);
    }

    @Test
    public void testGetCertificateChain_Active() throws Exception {

        final List<CertificateChain> expectedCertificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(
                expectedCertificateChains);

        final List<CertificateChain> actualCertificateChains = cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.ACTIVE);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test
    public void testCertificateChain_InActive() throws Exception {

        final List<CertificateChain> expectedCertificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.INACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE)).thenReturn(
                expectedCertificateChains);

        final List<CertificateChain> actualCertificateChains = cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.INACTIVE);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test
    public void testGetCertificateChain_Both_ActiveAndInActive() throws Exception {

        final CertificateStatus[] certificateStatus = { CertificateStatus.ACTIVE, CertificateStatus.INACTIVE };

        final List<CertificateChain> expectedCertificateChains = getCertificateChain(certificateStatus);

        final List<CertificateChain> actualCertificateChains = cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                certificateStatus);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test
    public void testGetCertificateChain_Duplicate_CertificateStatus() throws Exception {
        final CertificateStatus[] certStatus = { CertificateStatus.ACTIVE, CertificateStatus.INACTIVE };
        final List<CertificateChain> expectedCertificateChains = getCertificateChain(certStatus);

        final CertificateStatus[] certificateStatus = { CertificateStatus.ACTIVE, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE, CertificateStatus.INACTIVE };
        final List<CertificateChain> actualCertificateChains = cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                certificateStatus);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_Active_Certificate_Not_Found() throws Exception {

        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenThrow(
                new InvalidCAException());
        cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE);

    }

    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_InActive_Certificate_Not_Found() throws Exception {

        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE)).thenThrow(
                new InvalidCAException());
        cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE);

    }

    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCertificateChain_CertificateStatus_Revoked() throws Exception {

        cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.REVOKED);

    }

    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCertificateChain_Duplicate_CertificateStatus_Revoked() throws Exception {

        final CertificateStatus[] certStatus = { CertificateStatus.ACTIVE, CertificateStatus.ACTIVE, CertificateStatus.REVOKED };
        cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certStatus);

    }

    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCertificateChain_CertificateStatus_Expired() throws Exception {

        cAEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.EXPIRED);

    }

    private void assertCertificate(final Certificate generatedCertificate) {

        assertNotNull(generatedCertificate);
        assertEquals(certificate.getSerialNumber(), generatedCertificate.getSerialNumber());
        assertEquals(certificate.getNotBefore(), generatedCertificate.getNotBefore());
        assertEquals(certificate.getNotAfter(), generatedCertificate.getNotAfter());
        assertEquals(certificate.getStatus(), generatedCertificate.getStatus());
        assertEquals(certificate.getX509Certificate(), generatedCertificate.getX509Certificate());
        assertEquals(certificate.getId(), generatedCertificate.getId());
        assertEquals(certificate.getIssuedTime(), generatedCertificate.getIssuedTime());

    }

    @Test
    public void testRenewCertificate_ReIssueInfo() throws Exception {
        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        caReIssueInfo.setName(SetUPData.ROOT_CA_NAME);
        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(caEntity);

        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);

        Mockito.when(caEntity.getCertificateAuthority().getName()).thenReturn(SetUPData.ROOT_CA_NAME);

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);

        certificateData.setIssuerCA(caEntityData);
        certificateData.setSubjectDN("CN=ENMSubCA");
        certificateData.setSerialNumber(certificate.getSerialNumber());
        certificateData.setIssuerCertificate(certificateData);
        final List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
        certificateDatas.add(certificateData);
        Mockito.when(caPersistenceHelper.getCertificateDatas(SetUPData.ROOT_CA_NAME, CertificateStatus.ACTIVE)).thenReturn(certificateDatas);
        cAEntityCertificateManager.renewCertificate(caReIssueInfo, ReIssueType.CA);

    }

    @Test(expected = CANotFoundException.class)
    public void testRenewCertificate_ReIssueInfo_EntityNotFoundException() throws Exception {
        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        caReIssueInfo.setName(SetUPData.ROOT_CA_NAME);
        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenThrow(new EntityNotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND));
        cAEntityCertificateManager.renewCertificate(caReIssueInfo, ReIssueType.CA);

    }

    @Test
    public void testRekeyCertificate_ReIssueInfo() throws Exception {

        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        final CAEntity caEntity = entitySetUPData.getCAEntity();
        caReIssueInfo.setName(SetUPData.ROOT_CA_NAME);
        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(caEntity);
        final String CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS = "select c from CertificateData c where c.id in(select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p WHERE ec.certificateAuthorityData.name = :name and p.status in(:status)) ORDER BY c.id DESC";
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(persistenceManager.getEntityManager().createQuery(CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS)).thenReturn(query);
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        certificateData.setIssuerCA(caEntityData);
        certificateData.setSubjectDN("CN=ENMSubCA");
        certificateData.setSerialNumber(certificate.getSerialNumber());
        certificateData.setIssuerCertificate(certificateData);
        final List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
        certificateDatas.add(certificateData);
        Mockito.when(caPersistenceHelper.getCertificateDatas(SetUPData.SUB_CA_NAME, CertificateStatus.ACTIVE)).thenReturn(certificateDatas);
        cAEntityCertificateManager.rekeyCertificate(caReIssueInfo, ReIssueType.CA);

        Mockito.verify(entityHelper).getCAEntity(SetUPData.ROOT_CA_NAME);

        Mockito.verify(rekeyHandler).rekeyCertificate(caEntity, ReIssueType.CA);
    }

    @Test(expected = CANotFoundException.class)
    public void testRekeyCertificate_ReIssueInfo_EntityNotFoundException() throws Exception {

        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        caReIssueInfo.setName(SetUPData.ROOT_CA_NAME);
        Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenThrow(new EntityNotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND));
        cAEntityCertificateManager.rekeyCertificate(caReIssueInfo, ReIssueType.CA);
    }

    @Test
    public void testPublishCertificate() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);
        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);

        cAEntityCertificateManager.publishCertificate(SetUPData.ENTITY_NAME);

        Mockito.verify(tdpsPersistenceHandler).updateEntityData(SetUPData.ENTITY_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID);
        Mockito.verify(certificateEventNotifier).notify(EntityType.CA_ENTITY, SetUPData.ENTITY_NAME, TDPSPublishStatusType.PUBLISH, certificates);

    }

    @Test
    public void testPublishCertificate_IsExternalCA() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);

        caEntityData.setExternalCA(false);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);

        extCACertificatePersistanceHandler.updateIssuerAndSubjectForExtCertificate(SetUPData.ENTITY_NAME, certificates);
        cAEntityCertificateManager.publishCertificate(SetUPData.ENTITY_NAME);
        Mockito.verify(tdpsPersistenceHandler).updateEntityData(SetUPData.ENTITY_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID);
        Mockito.verify(certificateEventNotifier).notify(EntityType.CA_ENTITY, SetUPData.ENTITY_NAME, TDPSPublishStatusType.PUBLISH, certificates);

    }

    @Test(expected = CertificateServiceException.class)
    public void testPublishCertificate_CertificateServiceException() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);

        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);

        caEntityData.setExternalCA(false);

        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        cAEntityCertificateManager.publishCertificate(SetUPData.ENTITY_NAME);

    }

    @Test
    public void testUnPublishCertificate() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);
        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);

        cAEntityCertificateManager.unPublishCertificate(SetUPData.ENTITY_NAME);
        Mockito.verify(certificateEventNotifier).notify(EntityType.CA_ENTITY, SetUPData.ENTITY_NAME, TDPSPublishStatusType.UNPUBLISH, certificates);

    }

    @Test(expected = CertificateServiceException.class)
    public void testUnpublishCertificate_CertificateEncodinException() throws Exception {

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);
        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);

        cAEntityCertificateManager.unPublishCertificate(SetUPData.ENTITY_NAME);
    }

    @Test(expected = CertificateServiceException.class)
    public void testUnpublishCertificate_CertificateServiceException() throws Exception {

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);

        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateData.setIssuerCA(caEntityData);
        certificateData.setSubjectDN("CN=ENMSubCA");
        certificateData.setSerialNumber(certificate.getSerialNumber());
        final List<CertificateData> certificateDatas = new ArrayList<CertificateData>();

        certificateDatas.add(certificateData);
        Mockito.when(extCACertificatePersistanceHandler.getCertificateDatasForExtCA(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificateDatas);
        Mockito.when(
                extCertificateModelMapper.toObjectModel(extCACertificatePersistanceHandler.getCertificateDatasForExtCA(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)))
                .thenReturn(certificates);

        Mockito.doThrow(PersistenceException.class).when(tdpsPersistenceHandler).updateEntityData(SetUPData.ENTITY_NAME, EntityType.CA_ENTITY, false);

        cAEntityCertificateManager.unPublishCertificate(SetUPData.ENTITY_NAME);
    }

    @Test
    public void testGetCSR() throws Exception {
        Mockito.when(generateCSRHandler.getCSR(SetUPData.ROOT_CA_NAME)).thenReturn(pkcs10CertificationRequestHolder);
        cAEntityCertificateManager.getCSR(SetUPData.ROOT_CA_NAME);

    }

    @Test
    public void testGenerateCSR() throws Exception {
        Mockito.when(generateCSRHandler.generateCSR(SetUPData.ROOT_CA_NAME, true)).thenReturn(pkcs10CertificationRequestHolder);
        cAEntityCertificateManager.generateCSR(SetUPData.ROOT_CA_NAME, true);
    }

    @Test
    public void testGetRootCAEntity() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ENTITY_NAME)).thenReturn(caEntityData);

        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        cAEntityCertificateManager.getRootCAEntity(SetUPData.ROOT_CA_NAME);
    }

    @Test(expected = CertificateServiceException.class)
    public void testGetRootCAEntity_CertificateServiceException() throws Exception {
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenThrow(new EntityServiceException(INTERNAL_ERROR));
        cAEntityCertificateManager.getRootCAEntity(SetUPData.ROOT_CA_NAME);
    }

    @Test(expected = CANotFoundException.class)
    public void testGetRootCAEntity_CANotFoundException() throws Exception {
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        Mockito.when(caPersistenceHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenThrow(new CANotFoundException(ErrorMessages.ROOT_CA_NOT_FOUND));
        cAEntityCertificateManager.getRootCAEntity(SetUPData.ROOT_CA_NAME);
    }

    @Test
    public void testListIssuedCertificates() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caCertificateIdentifier.getCaName()).thenReturn(SetUPData.ROOT_CA_NAME);
        Mockito.when(caCertificateIdentifier.getCerficateSerialNumber()).thenReturn("1234");
        Mockito.when(caPersistenceHelper.getCAEntityData(SetUPData.ROOT_CA_NAME, "1234")).thenReturn(caEntityData);

        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateData.setIssuerCA(caEntityData);
        certificateData.setSubjectDN("CN=ENMSubCA");
        certificateData.setSerialNumber(certificate.getSerialNumber());
        final Set<CertificateData> certificateDatas = caEntityData.getCertificateAuthorityData().getCertificateDatas();

        Mockito.when(certificateHelper.getMappedCertificateData(certificateDatas, caCertificateIdentifier.getCerficateSerialNumber())).thenReturn(certificateData);

        final Long[] issuerCertificateIds = new Long[] { certificateData.getId() };

        final List<CertificateInfo> certificateInfoList = null;
        Mockito.when(certificatePersistenceHelper.getCertificatesInfoByIssuerCA(issuerCertificateIds, CertificateStatus.ACTIVE)).thenReturn(certificateInfoList);

        cAEntityCertificateManager.listIssuedCertificates(caCertificateIdentifier, CertificateStatus.ACTIVE);
    }

    @Test(expected = CANotFoundException.class)
    public void testListIssuedCertificates_CANotFoundException() throws Exception {

        cAEntityCertificateManager.listIssuedCertificates(caCertificateIdentifier, CertificateStatus.ACTIVE);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testListIssuedCertificates_CertificateNotFoundException() throws Exception {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);

        Mockito.when(caCertificateIdentifier.getCaName()).thenReturn(SetUPData.ROOT_CA_NAME);
        Mockito.when(caCertificateIdentifier.getCerficateSerialNumber()).thenReturn("1234");
        Mockito.when(caPersistenceHelper.getCAEntityData(SetUPData.ROOT_CA_NAME, "1234")).thenReturn(caEntityData);

        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateData.setIssuerCA(caEntityData);
        certificateData.setSubjectDN("CN=ENMSubCA");
        certificateData.setSerialNumber(certificate.getSerialNumber());
        final Set<CertificateData> certificateDatas = caEntityData.getCertificateAuthorityData().getCertificateDatas();

        Mockito.when(certificateHelper.getMappedCertificateData(certificateDatas, caCertificateIdentifier.getCerficateSerialNumber())).thenReturn(null);

        cAEntityCertificateManager.listIssuedCertificates(caCertificateIdentifier, CertificateStatus.ACTIVE);
    }

    @Test
    public void testRenewCertificateRootCACertRevocationException() {

        try {

            caEntity = entitySetUPData.getCAEntity();

            Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(getCAEntity());
            Mockito.when(caPersistenceHelper.getCertificateDatas(Mockito.anyString(), Mockito.any(CertificateStatus.class))).thenReturn(getCertificateDataList());

            certificateAuthority.setIssuerExternalCA(false);
            caEntity.setCertificateAuthority(certificateAuthority);

            cAEntityCertificateManager.renewCertificate(getCAReIssueInfo(), ReIssueType.CA);
        } catch (RootCertificateRevocationException rootCertificateRevocationException) {
            assertEquals(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED, rootCertificateRevocationException.getMessage());
        } catch (CertificateException | DatatypeConfigurationException | IOException | AssertionError exception) {
            fail(exception.getMessage());
        }
    }

    @Test
    public void testRenewCertificateEXtCASignedRootCACertRevocationException() {

        try {

            caEntity = entitySetUPData.getCAEntity();

            Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(getCAEntity());
            Mockito.when(caPersistenceHelper.getCertificateDatas(Mockito.anyString(), Mockito.any(CertificateStatus.class))).thenReturn(getCertificateDataList());

            certificateAuthority.setIssuerExternalCA(true);
            caEntity.setCertificateAuthority(certificateAuthority);

            cAEntityCertificateManager.renewCertificate(getCAReIssueInfo(), ReIssueType.CA);
        } catch (RootCertificateRevocationException rootCertificateRevocationException) {
            assertEquals(ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED, rootCertificateRevocationException.getMessage());
        } catch (CertificateException | DatatypeConfigurationException | IOException | AssertionError exception) {
            fail(exception.getMessage());
        }
    }

    @Test
    public void testRekeyCertificateRootCACertRevocationException() {

        try {

            caEntity = entitySetUPData.getCAEntity();

            Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(getCAEntity());
            Mockito.when(caPersistenceHelper.getCertificateDatas(Mockito.anyString(), Mockito.any(CertificateStatus.class))).thenReturn(getCertificateDataList());

            certificateAuthority.setIssuerExternalCA(false);
            caEntity.setCertificateAuthority(certificateAuthority);

            cAEntityCertificateManager.rekeyCertificate(getCAReIssueInfo(), ReIssueType.CA);
        } catch (RootCertificateRevocationException rootCertificateRevocationException) {
            assertEquals(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED, rootCertificateRevocationException.getMessage());
        } catch (CertificateException | DatatypeConfigurationException | IOException | AssertionError exception) {
            fail(exception.getMessage());
        }
    }

    @Test
    public void testRekeyCertificateEXtCASignedRootCACertRevocationException() {

        try {

            Mockito.when(entityHelper.getCAEntity(SetUPData.ROOT_CA_NAME)).thenReturn(getCAEntity());
            Mockito.when(caPersistenceHelper.getCertificateDatas(Mockito.anyString(), Mockito.any(CertificateStatus.class))).thenReturn(getCertificateDataList());

            certificateAuthority.setIssuerExternalCA(true);
            caEntity.setCertificateAuthority(certificateAuthority);

            cAEntityCertificateManager.rekeyCertificate(getCAReIssueInfo(), ReIssueType.CA);
        } catch (RootCertificateRevocationException rootCertificateRevocationException) {
            assertEquals(ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED, rootCertificateRevocationException.getMessage());
        } catch (CertificateException | DatatypeConfigurationException | IOException | AssertionError exception) {
            fail(exception.getMessage());
        }
    }

    private CAEntityData getCAEntityData() {
        final CAEntityData caEntityData = new CAEntityData();

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setRootCA(true);

        certificateAuthorityData.setIssuerExternalCA(true);

        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        return caEntityData;
    }

    private List<CertificateChain> getCertificateChain(final CertificateStatus[] certificateStatus) throws CertificateException, IOException {
        final List<CertificateChain> expectedCertificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        expectedCertificateChains.addAll(setUPData.getCAEntityCertificateChain(CertificateStatus.INACTIVE));
        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certificateStatus)).thenReturn(
                expectedCertificateChains);
        return expectedCertificateChains;
    }

    private CAEntity getCAEntity() throws CertificateException, DatatypeConfigurationException, IOException {

        caEntity = entitySetUPData.getCAEntity();

        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setRootCA(true);
        certificateAuthority.setIssuerExternalCA(true);
        caEntity.setCertificateAuthority(certificateAuthority);

        return caEntity;
    }

    private List<CertificateData> getCertificateDataList() {

        final CertificateData certData = new CertificateData();
        final List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
        certificateDatas.add(certData);

        return certificateDatas;
    }

    private CAReIssueInfo getCAReIssueInfo() {

        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        caReIssueInfo.setName(SetUPData.ROOT_CA_NAME);

        return caReIssueInfo;
    }
}
