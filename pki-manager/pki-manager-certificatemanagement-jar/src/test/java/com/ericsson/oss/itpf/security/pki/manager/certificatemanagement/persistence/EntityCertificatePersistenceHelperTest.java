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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.persistence;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.CertificateManagementBaseTest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.CertificateGenerationInfoSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SubjectSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertificatePersistenceHelperTest extends CertificateManagementBaseTest {

    @InjectMocks
    EntityCertificatePersistenceHelper entityPersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    CertificateModelMapperV1 certificateModelMapperV1;

    @Mock
    CACertificatePersistenceHelper cAPersistenceHelper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    private static SetUPData setUPData;
    private static SubjectSetUPData subjectData;
    private static CertificateGenerationInfoSetUPData certificateGenerationInfoSetUPData;
    final static private String entityName = "Entity";
    private static final String ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS = "select c from CertificateData c where c.status in(:status) and c.id in(select p.id from EntityData ec inner join ec.entityInfoData.certificateDatas p  WHERE ec.entityInfoData.name = :name) ORDER BY c.id DESC";
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @BeforeClass
    public static void setUp() throws Exception {

        setUPData = new SetUPData();
        subjectData = new SubjectSetUPData();
        certificateGenerationInfoSetUPData = new CertificateGenerationInfoSetUPData();

    }

    /**
     * Method to test the entity certificate to be stored.
     * 
     * @throws Exception
     */
    @Test
    public void testStoreCertificate() throws Exception {

        final Subject subject = subjectData.getSubject("Entity");
        final Entity entity = setUPData.getEntity(subject, null);

        final Certificate certificate = setUPData.getEntityCertificate();
        final CertificateGenerationInfo certGenInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_Entity();

        final EntityData entityData = setUPData.createEntityData(SetUPData.ENTITY_NAME);
        Mockito.when(persistenceManager.findEntity(EntityData.class, entity.getEntityInfo().getId())).thenReturn(entityData);

        final CertificateData certificateData = mockCertificateData(certificate);

        mockCertGenInfoData(certGenInfo);
        final List<CertificateData> certificateDataList = new ArrayList<CertificateData>();
        certificateDataList.add(certificateData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDataList);

        Mockito.when(persistenceManager.updateEntity(entityData)).thenReturn(entityData);

        entityPersistenceHelper.storeCertificate(entity, certGenInfo, certificate);

        Mockito.verify(persistenceManager).createEntity(certificateData);

    }

    private void mockCertGenInfoData(final CertificateGenerationInfo certGenInfo) {

        final CertificateGenerationInfoData certGenInfoData = new CertificateGenerationInfoData();
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId())).thenReturn(certGenInfoData);

        Mockito.when(persistenceManager.updateEntity(certGenInfoData)).thenReturn(certGenInfoData);
    }

    /**
     * Mock the issuerCAEntityData and CertificateData.
     * 
     * @param certificate
     * @return CertificateData
     * 
     * @throws CertificateException
     * @throws CertificateEncodingException
     * @throws IOException
     */
    private CertificateData mockCertificateData(final Certificate certificate) throws CertificateException, CertificateEncodingException, IOException {

        final CAEntityData issuerCAEntityData = setUPData.createCAEntityData(SetUPData.SUB_CA_NAME, false);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(), Constants.CA_NAME_PATH)).thenReturn(issuerCAEntityData);

        final CertificateData certificateData = setUPData.createCertificateData("12345");
        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);

        Mockito.doNothing().when(persistenceManager).createEntity(certificateData);

        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getId())).thenReturn(certificateData);

        return certificateData;
    }

    /**
     * Method to test storeCertificate method when DataException occurred.
     * 
     * @throws Exception
     */
    @Test(expected = PersistenceException.class)
    public void testStoreCertificate_DataExeption() throws Exception {

        final Subject subject = subjectData.getSubject("Entity");
        final Entity entity = setUPData.getEntity(subject, null);

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");

        final CertificateGenerationInfo certGenInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_Entity();

        Mockito.when(persistenceManager.findEntity(EntityData.class, entity.getEntityInfo().getId())).thenThrow(new PersistenceException("Exception while retrieving the entity from database"));

        entityPersistenceHelper.storeCertificate(entity, certGenInfo, certificate);
    }

    /**
     * Method to test getCertificates method.
     * 
     * @throws Exception
     */
    @Test
    public void testGetCertificates() throws Exception {

        final CertificateData certificateData = setUPData.createCertificateData("12345");

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        final Certificate certificate = setUPData.toCertificate(certificateData);
        Mockito.when(certificateModelMapperV1.toApi(Arrays.asList(certificateData), MappingDepth.LEVEL_0)).thenReturn(Arrays.asList(certificate));

        final List<Certificate> certificates = entityPersistenceHelper.getCertificates(setUPData.ENTITY_NAME,MappingDepth.LEVEL_0, CertificateStatus.ACTIVE);

        assertCertificate(certificateData, certificates.get(0));
    }

    /**
     * Method to test getCertificates method when DataException occurred.
     *
     * @throws Exception
     */
    @Test(expected = PersistenceException.class)
    public void testGetCertificates_DataExeption() throws Exception {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenThrow(new PersistenceException("Exception while retrieving the certificates from database"));

        entityPersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for retrieving EntityData for the given Entity.
     */
    @Test
    public void testGetEntityData() throws Exception {

        final EntityData entityData = setUPData.createEntityData(SetUPData.ENTITY_NAME);
        Mockito.when(persistenceManager.findEntityByName(EntityData.class, SetUPData.ENTITY_NAME, Constants.ENTITY_NAME_PATH)).thenReturn(entityData);

        final EntityData actualEntityData = entityPersistenceHelper.getEntityData(SetUPData.ENTITY_NAME);

        assertEntityData(entityData, actualEntityData);
    }

    /**
     * Test Case for checking EntityNotFoundException if the given entity is not found in the DB.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityData_EntityNotFound() {

        final String entityName = null;

        Mockito.when(persistenceManager.findEntityByName(EntityData.class, entityName, Constants.ENTITY_NAME_PATH)).thenReturn(null);

        entityPersistenceHelper.getEntityData(entityName);

    }

    /**
     * Test Case for checking PersistenceException in case of any problem occurs while doing database operations.
     */
    @Test(expected = EntityServiceException.class)
    public void testGetEntityData_PersistenceException() {

        Mockito.when(persistenceManager.findEntityByName(EntityData.class, entityName, Constants.ENTITY_NAME_PATH)).thenThrow(new PersistenceException());

        entityPersistenceHelper.getEntityData(entityName);
    }

    /**
     * Test Case for to check {@link CertificateGenerationInfo} is stored in the database or not.
     * 
     * @throws IOException
     */
    @Test
    public void testStoreCertificateGenerateInfo() throws IOException {

        final CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();
        final CertificateRequest certificateRequest = new CertificateRequest();
        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        Mockito.when(certificateModelMapper.toCertificateGenerationInfoData(certificateGenerationInfo)).thenReturn(certificateGenerationInfoData);
        Mockito.doNothing().when(persistenceManager).createEntity(certificateGenerationInfoData);
        Mockito.when(certificateModelMapper.toCertificateRequestData(certificateRequest)).thenReturn(certificateRequestData);
        Mockito.doNothing().when(persistenceManager).createEntity(certificateRequestData);
        Mockito.when(persistenceManager.updateEntity(certificateGenerationInfoData)).thenReturn(certificateGenerationInfoData);

        entityPersistenceHelper.storeCertificateGenerateInfo(certificateGenerationInfo);
    }
}
