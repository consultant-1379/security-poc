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
package com.ericsson.oss.itpf.security.pki.manager.revocation.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.times;

import java.math.BigInteger;
import java.util.*;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class RevocationPersistenceHelperTest {

    @InjectMocks
    RevocationPersistenceHelper revocationPersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    private EntityManager entityManager;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    EntityCertificatePersistenceHelper entityPersistenceHelper;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    private RevocationRequestData revocationRequestData;

    @Mock
    private Query query;

    @Mock
    private SystemRecorder systemRecorder;

    private String entityName;
    private EntityData entityData;
    private Date date;

    private Certificate certificate;

    private CAEntityData caEntityData;
    private CertificateIdentifier certificateIdentifier;
    private CertificateData certificateData;
    private DNBasedCertificateIdentifier dnBasedCertificateIdentifier;

    private ArrayList<BigInteger> entityId;

    private String caEntityQuery;
    private String entityQueryString;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        entityName = "ENM_SubCA2";

        date = new Date();

        certificate = prepareActiveCertificate();

        caEntityData = prepareCAEntityData();

        entityData = prepareEntityData();

        certificateIdentifier = prepareCertificateIdentifier();

        certificateData = prepareCertificateData();

        dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();

        entityId = new ArrayList<BigInteger>();
        entityId.add(BigInteger.valueOf(1));

        caEntityQuery = "select ca_id from ca_certificate where certificate_id = 10101";

        entityQueryString = "select entity_id from entity_certificate where certificate_id = 10101";

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getCertificate(com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier)}
     * .
     */
    @Test
    public void testGetCertificate() {

        Mockito.when(certificatePersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);

        Certificate certificateReturn = revocationPersistenceHelper.getCertificate(certificateIdentifier);

        assertNotNull(certificateReturn);
        assertEquals(certificateReturn, certificate);

    }

    @Test(expected = RevocationServiceException.class)
    public void testGetCertificateThrowsRevocationServiceException() {

        Mockito.when(certificatePersistenceHelper.getCertificate(certificateIdentifier)).thenThrow(new CertificateServiceException());

        revocationPersistenceHelper.getCertificate(certificateIdentifier);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getEntityData(java.lang.String)} .
     */
    @Test
    public void testGetEntityData() {

        Mockito.when(entityPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);

        EntityData entityDataReturn = revocationPersistenceHelper.getEntityData(entityName);

        Mockito.verify(entityPersistenceHelper, times(1)).getEntityData(entityName);
        assertNotNull(entityDataReturn);
        assertEquals(entityDataReturn, entityData);

    }

    /**
     * Test method for getEntityData RevocationServiceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testGetEntityDataThrowsRevocationServiceException() {

        Mockito.when(entityPersistenceHelper.getEntityData(entityName)).thenThrow(new PersistenceException());

        revocationPersistenceHelper.getEntityData(entityName);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getCAEntityData(java.lang.String)} .
     */
    @Test
    public void testGetCAEntityData() {

        Mockito.when(caPersistenceHelper.getCAEntity(entityName)).thenReturn(caEntityData);

        CAEntityData caEntityDataReturn = revocationPersistenceHelper.getCAEntityData(entityName);

        assertNotNull(caEntityDataReturn);
        assertEquals(caEntityDataReturn, caEntityData);

    }

    /**
     * Test method for testGetCAEntityData PersistenceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testGetCAEntityData_PersistenceException() {

        Mockito.when(caPersistenceHelper.getCAEntity(entityName)).thenThrow(new PersistenceException());

        revocationPersistenceHelper.getCAEntityData(entityName);
    }

    /**
     * Test method for testGetCAEntityData CANotFoundException.
     */
    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testGetCAEntityData_CANotFoundException() {

        Mockito.when(caPersistenceHelper.getCAEntity(entityName)).thenThrow(new CANotFoundException());

        revocationPersistenceHelper.getCAEntityData(entityName);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getCertificateData(com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate)} .
     */
    @Test
    public void testGetCertificateData() {

        Mockito.when(certificatePersistenceHelper.getCertificateData(certificate)).thenReturn(certificateData);

        CertificateData certificateDataReturn = revocationPersistenceHelper.getCertificateData(certificate);

        assertNotNull(certificateDataReturn);
        assertEquals(certificateDataReturn.getId(), certificateData.getId());

    }

    /**
     * Test method for testGetCertificateData RevocationServiceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testGetCertificateData_RevocationServiceException() {

        Mockito.when(certificatePersistenceHelper.getCertificateData(certificate)).thenThrow(new CertificateServiceException());

        revocationPersistenceHelper.getCertificateData(certificate);
    }

    /**
     * Test method for getCertificateList
     */
    @Test
    public void testGetCertificateList() {
        List<Certificate> certificateList = new ArrayList<Certificate>();
        certificateList.add(certificate);
        dnBasedCertificateIdentifier.setCerficateSerialNumber("12345");
        Mockito.when(certificatePersistenceHelper.getCertificateBySerialNumber(dnBasedCertificateIdentifier.getCerficateSerialNumber())).thenReturn(certificateList);
        certificateList = revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier);
        assertNotNull(certificateList);
    }

    /**
     * Test method for getCertificateList RevocationServiceException
     */
    @Test(expected = RevocationServiceException.class)
    public void testGetCertificateList_RevocationServiceException() {

        dnBasedCertificateIdentifier.setCerficateSerialNumber("12345");
        Mockito.when(certificatePersistenceHelper.getCertificateBySerialNumber(dnBasedCertificateIdentifier.getCerficateSerialNumber())).thenThrow(new CertificateServiceException());
        revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#storeRevocationRequestData(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.RevocationRequestData, java.util.List, com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason, java.util.Date)}
     * .
     */
    @Test
    public void testStoreRevocationRequestData() {

        revocationPersistenceHelper.storeRevocationRequestData(new RevocationRequestData(), new LinkedList<CertificateData>(), RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(logger, times(1)).debug("Store revocation request details");

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#storeRevocationRequestData(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.RevocationRequestData, java.util.List, com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason, java.util.Date)}
     * .
     */
    @Test(expected = RevocationServiceException.class)
    public void testStoreRevocationRequestData_PersistenceException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).createEntity((RevocationRequestData) Mockito.any());

        revocationPersistenceHelper.storeRevocationRequestData(new RevocationRequestData(), new LinkedList<CertificateData>(), RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#updateCertificateStatus(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData, com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus)}
     * .
     */
    @Test
    public void testUpdateCertificateStatusForRevocationRequest() {

        revocationPersistenceHelper.updateCertificateStatusForRevocationRequest(revocationRequestData);

        Mockito.verify(logger, times(1)).debug("Updating certificateStatus for revocation request ");
    }

    /**
     * Test method for updateCertificateStatusForRevocationRequest RevocationServiceException
     */
    @Test(expected = RevocationServiceException.class)
    public void testUpdateCertificateStatusForRevocationRequest_RevocationServiceException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(revocationRequestData);

        revocationPersistenceHelper.updateCertificateStatusForRevocationRequest(revocationRequestData);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#updateRevocationRequestStatus(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.RevocationRequestData, com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus)}
     * .
     */
    @Test
    public void testUpdateRevocationRequestStatus() {

        revocationPersistenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.REVOKED);

        Mockito.verify(revocationRequestData, times(1)).setStatus(RevocationRequestStatus.REVOKED);
    }

    /**
     * Test method for updateRevocationRequestStatus RevocationServiceException
     */
    @Test(expected = RevocationServiceException.class)
    public void testUpdateRevocationRequestStatus_RevocationServiceException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(revocationRequestData);

        revocationPersistenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.REVOKED);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getCaEntityById(com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate)} .
     */
    @Test
    public void testGetCaEntityById() {

        Mockito.when(entityManager.createNativeQuery(caEntityQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        Mockito.when(persistenceManager.findEntity(CAEntityData.class, revocationPersistenceHelper.getCaEntityIdFromCertificateId(certificate.getId()))).thenReturn(caEntityData);
        CAEntityData caEntity = revocationPersistenceHelper.getCaEntityById(certificate.getId());
        assertNotNull(caEntity);
        assertNotNull(caEntity.getId());

    }

    /**
     * Test method for getCaEntityById with RevocationServiceException
     */
    @Test(expected = RevocationServiceException.class)
    public void testGetCaEntityById_RevocationServiceException() {

        Mockito.when(entityManager.createNativeQuery(caEntityQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        Mockito.when(persistenceManager.findEntity(CAEntityData.class, revocationPersistenceHelper.getCaEntityIdFromCertificateId(certificate.getId()))).thenThrow(new PersistenceException());

        revocationPersistenceHelper.getCaEntityById(certificate.getId());
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getEntityById(com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate)} .
     */
    @Test
    public void testGetEntityById() {

        Mockito.when(entityManager.createNativeQuery(entityQueryString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        Mockito.when(persistenceManager.findEntity(EntityData.class, revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId()))).thenReturn(entityData);
        EntityData entityData = revocationPersistenceHelper.getEntityById(certificate);
        assertNotNull(entityData);
        assertNotNull(entityData.getId());
    }

    /**
     * Test method for getEntityById with EntityNotFoundException
     */
    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testGetEntityById_EntityNotFoundException() {

        Mockito.when(entityManager.createNativeQuery(entityQueryString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        Mockito.when(persistenceManager.findEntity(EntityData.class, revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId()))).thenThrow(
                new javax.persistence.EntityNotFoundException());
        revocationPersistenceHelper.getEntityById(certificate);
    }

    /**
     * Method to test GetEntityById for RevocationServiceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testGetEntityById_PersistenceException() {

        Mockito.when(entityManager.createNativeQuery(entityQueryString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        Mockito.when(persistenceManager.findEntity(EntityData.class, revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId()))).thenThrow(new PersistenceException());
        revocationPersistenceHelper.getEntityById(certificate);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getCaEntityIdFromCertificateId(long)} .
     */
    @Test
    public void testGetCaEntityIdFromCertificateId() {
        Mockito.when(entityManager.createNativeQuery(caEntityQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        long entity = revocationPersistenceHelper.getCaEntityIdFromCertificateId(certificate.getId());
        assertNotNull(entity);
        assertEquals(entity, 1);
    }

    /**
     * Test method for getCaEntityIdFromCertificateId EntityNotFoundException
     */
    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testGetCaEntityIdFromCertificateId_EntityNotFoundException() {
        entityId = new ArrayList<BigInteger>();
        Mockito.when(entityManager.createNativeQuery(caEntityQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        revocationPersistenceHelper.getCaEntityIdFromCertificateId(certificate.getId());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper#getEntityIdFromCertificateId(long)} .
     */
    @Test
    public void testGetEntityIdFromCertificateId() {
        Mockito.when(entityManager.createNativeQuery(entityQueryString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        long entity = revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId());
        assertNotNull(entity);
        assertEquals(entity, 1);
    }

    /**
     * Test method for getEntityIdFromCertificateId EntityNotFoundException
     */
    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testGetEntityIdFromCertificateId_EntityNotFoundException() {
        entityId = new ArrayList<BigInteger>();
        Mockito.when(entityManager.createNativeQuery(entityQueryString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityId);
        revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId());
    }

    private Certificate prepareActiveCertificate() {

        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.ACTIVE);

        return certificate;
    }

    private EntityData prepareEntityData() {

        EntityData entityData = new EntityData();
        entityData.setId(101010);
        entityData.setPublishCertificatetoTDPS(true);

        return entityData;
    }

    private CAEntityData prepareCAEntityData() {

        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setEntityProfileData(new EntityProfileData());
        caEntityData.setExternalCA(false);
        caEntityData.setId(101010101);
        caEntityData.setKeyGenerationAlgorithm(new AlgorithmData());
        caEntityData.setPublishCertificatetoTDPS(false);
        caEntityData.setCertificateAuthorityData(prepareCertificateAuthorityData());

        return caEntityData;
    }

    private CertificateAuthorityData prepareCertificateAuthorityData() {

        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("ENMCA");
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setSubjectAltName("AltName");
        certificateAuthorityData.setSubjectDN("SubDN");

        return certificateAuthorityData;
    }

    private CertificateIdentifier prepareCertificateIdentifier() {

        CertificateIdentifier certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName("issuerN");
        certificateIdentifier.setSerialNumber("565670");

        return certificateIdentifier;
    }

    private CertificateData prepareCertificateData() {

        CertificateData certificateData = new CertificateData();
        certificateData.setId(111000);
        certificateData.setIssuedTime(new Date());

        return certificateData;
    }
}
