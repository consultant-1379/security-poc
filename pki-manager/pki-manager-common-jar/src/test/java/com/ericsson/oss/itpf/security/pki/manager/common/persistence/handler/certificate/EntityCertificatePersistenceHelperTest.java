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

import static org.junit.Assert.*;

import java.io.IOException;
/**
 * @author emcgtom
 */
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertificatePersistenceHelperTest {

    @InjectMocks
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    CertificateModelMapperV1 certificateModelMapperV1;

    @Mock
    Query query;

    @Mock
    Logger logger;

    private Entity entity;
    private CertificateGenerationInfo certGenInfo;
    private CertificateGenerationInfoData certGenInfoData;
    private CertificateRequest certificateReq;
    private CertificateRequestData certReqData;
    private Certificate certificate;
    private CertificateData certificateData;
    private Set<CertificateData> certificateDatas;
    private EntityInfo entityInfo;
    private EntityData entityData;
    private EntityInfoData entityInfoData;

    private static final String ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS = "select c from CertificateData c where c.status in(:status) and c.id in(select p.id from EntityData ec inner join ec.entityInfoData.certificateDatas p  WHERE ec.entityInfoData.name = :name) ORDER BY c.id DESC";
    private static final String ENTITY_NAMES_BY_STATUS = "SELECT ee.entityInfoData.name FROM EntityData ee WHERE ee.entityInfoData.status in (:status)";

    @Before
    public void setUp() {
        entity = new Entity();
        certGenInfo = new CertificateGenerationInfo();
        certificate = new Certificate();
        certificateData = new CertificateData();
        entityInfo = new EntityInfo();
        entityData = new EntityData();
        entityInfoData = new EntityInfoData();
        certificateDatas = new HashSet<CertificateData>();
        certGenInfoData = new CertificateGenerationInfoData();
        certificateReq = new CertificateRequest();
        certReqData = new CertificateRequestData();

        entityInfo.setName("entityName");
        entityInfo.setId(10101);
        entity.setEntityInfo(entityInfo);

        certificate = new Certificate();
        certificate.setId(101);
        certificate.setIssuedTime(new Date());
        certificate.setSerialNumber("10101");
        certificate.setStatus(CertificateStatus.ACTIVE);

        certificateData.setSerialNumber("10101");
        certificateData.setStatus(1);
        certificateDatas.add(certificateData);
        entityInfoData.setCertificateDatas(certificateDatas);
        entityInfoData.setName("entityName");
        entityData.setEntityInfoData(entityInfoData);
    }

    @Test
    public void testStoreCertificate() throws CertificateEncodingException, PersistenceException {

        Mockito.when(persistenceManager.findEntity(EntityData.class, entity.getEntityInfo().getId())).thenReturn(entityData);
        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);
        Mockito.when(persistenceManager.findEntity(CertificateData.class, certificateData.getId())).thenReturn(certificateData);
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId())).thenReturn(certGenInfoData);
        final List<CertificateData> certificateDataList = new ArrayList<CertificateData>();
        certificateDataList.add(certificateData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDataList);
        entityCertificatePersistenceHelper.storeCertificate(entity, certGenInfo, certificate);

        Mockito.verify(persistenceManager).updateEntity(certGenInfoData);
    }

    @Test
    public void testGetCertificates() throws CertificateException, PersistenceException, IOException {
        final List<CertificateData> certificateDataList = new ArrayList<CertificateData>();
        certificateDataList.add(certificateData);


        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDataList);

        entityCertificatePersistenceHelper.getCertificates(entity.getEntityInfo().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE);

        Mockito.verify(certificateModelMapperV1).toApi(certificateDataList, MappingDepth.LEVEL_0);
    }

    @Test
    public void testGetEntityData() {
        Mockito.when(persistenceManager.findEntityByName(EntityData.class, entity.getEntityInfo().getName(), Constants.ENTITY_NAME_PATH)).thenReturn(entityData);

        assertEquals(entityData, entityCertificatePersistenceHelper.getEntityData(entity.getEntityInfo().getName()));
    }

    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityDataEntityNotFoundException() {

        Mockito.when(persistenceManager.findEntityByName(EntityData.class, entity.getEntityInfo().getName(), Constants.ENTITY_NAME_PATH)).thenReturn(null);

        entityCertificatePersistenceHelper.getEntityData(entity.getEntityInfo().getName());
    }

    @Test
    public void testStoreCertificateGenerationInfo() throws IOException {

        Mockito.when(certificateModelMapper.toCertificateGenerationInfoData(certGenInfo)).thenReturn(certGenInfoData);
        Mockito.when(certificateModelMapper.toCertificateRequestData(certificateReq)).thenReturn(certReqData);
        entityCertificatePersistenceHelper.storeCertificateGenerateInfo(certGenInfo);
    }
    @Test
    public void testGetExpiredEntityCertificatesToUnpublish() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(ENTITY_NAMES_BY_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList("EENAME1"));

        Query query1 = Mockito.mock(Query.class);
        Mockito.when(entityManager.createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS)).thenReturn(query1);

        certificateData.setPublishedToTDPS(true);
        Mockito.when(query1.getResultList()).thenReturn(Arrays.asList(certificateData));
        try {
            Mockito.when(certificateModelMapper.toObjectModel(Arrays.asList(certificateData))).thenReturn(Arrays.asList(certificate));
        } catch (CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }

        final Map<String, List<Certificate>> entityCertsMap = entityCertificatePersistenceHelper.getExpiredEntityCertificatesToUnpublish();
        assertFalse(entityCertsMap.isEmpty());
    }

    @Test
    public void testGetAllNameByStatus() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(ENTITY_NAMES_BY_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList("CANAME1"));

        final List<String> caNames = entityCertificatePersistenceHelper.getAllEntityNameByStatus(EntityStatus.ACTIVE, EntityStatus.INACTIVE);
        assertNotNull(caNames);
        assertFalse(caNames.isEmpty());
    }
}
