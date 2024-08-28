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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class TDPSPersistenceHandlerTest {

    @InjectMocks
    TDPSPersistenceHandler tDPSPersistenceHandler;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    static String entityName = "caName";

    @Mock
    EntityData entityData;
    @Mock
    List<Certificate> certificates;

    @Mock
    AbstractEntity abstractEntity;

    @Mock
    Entity entity;
    @Mock
    CAEntity cAEnity;

    @Mock
    CertificateData certificateData;

    @Mock
    CAEntityData cAEntityData;

    @Mock
    Set<CertificateData> setcertificateDatas;

    @Mock
    EntityInfoData entityInfoData;

    @Mock
    Set<CertificateData> certificateDatas;

    @Mock
    CertificateAuthorityData certificateAuthorityData;

    @Mock
    List<CAEntityData> caEntityDatas;

    @Mock
    Map<String, Object> parameters;

    @Mock
    List<EntityData> entityDatas;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Test
    public void testGetPublishedCertificatesByType() throws CertificateException, PersistenceException, IOException {
        List<CAEntityData> caEntityDatas = new ArrayList<CAEntityData>();
        CAEntityData caEntityData = getCAEntityData();
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("rootCA");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityDatas.add(caEntityData);
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("publishCertificatetoTDPS", true);
        Mockito.when(persistenceManager.findEntitiesWhere(CAEntityData.class, parameters)).thenReturn(caEntityDatas);
        entityName = "rootCA";

        CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(new byte[] { 1, 2, 2 });
        certificateData.setId(1);
        certificateData.setPublishedToTDPS(true);
        certificateData.setIssuerCA(caEntityData);

        List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
        certificateDatas.add(certificateData);

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(entityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificateDatas(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificateDatas);
        tDPSPersistenceHandler.getPublishedCertificatesByType(EntityType.CA_ENTITY);
    }

    @Test
    public void testGetPublishedCertificatesByTypeForEntity() throws CertificateException, PersistenceException, IOException {
        tDPSPersistenceHandler.getPublishedCertificatesByType(EntityType.ENTITY);
    }

    @Test
    public void testUpdateCertificateData() throws CertificateException, PersistenceException, IOException {
        String entityName = "CAENTITY";
        String issuerName = "ISSUER";
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(entityName)).thenReturn(cAEntityData);
        tDPSPersistenceHandler.updateCertificateData(EntityType.CA_ENTITY, entityName, issuerName, "345345", true);
    }

    @Test
    public void testUpdateEntityData() throws CertificateException, PersistenceException, IOException {
        String entityName = "CAENTITY";
        tDPSPersistenceHandler.updateEntityData(entityName, EntityType.CA_ENTITY, true);
    }

    @Test
    public void testUpdateEntityDataForEntity() throws CertificateException, PersistenceException, IOException {
        String entityName = "ENTITY";
        tDPSPersistenceHandler.updateEntityData(entityName, EntityType.ENTITY, true);
    }

    @Test
    public void getPublishedCertificatesByEntityTypeTest() throws CertificateException, PersistenceException, IOException {
        tDPSPersistenceHandler.getPublishedCertificatesByType(EntityType.ENTITY);
    }

    @Test
    public void getPublishedCertificatesByCATypeTest() throws CertificateException, PersistenceException, IOException {
        Mockito.when(persistenceManager.findEntitiesWhere(CAEntityData.class, parameters)).thenReturn(caEntityDatas);
        tDPSPersistenceHandler.getPublishedCertificatesByType(EntityType.CA_ENTITY);
    }

    @Test
    public void testGetCertificateDatas() throws CertificateException, PersistenceException, IOException {
        String entityName = "CAENTITY";

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(entityName)).thenReturn(cAEntityData);
        Mockito.when(cAEntityData.isExternalCA()).thenReturn(false);
        tDPSPersistenceHandler.getCertificateDatas(EntityType.CA_ENTITY, entityName, CertificateStatus.ACTIVE);
    }

    @Test
    public void updateCertificateCAEntityData() throws EntityNotFoundException, PersistenceException, CertificateException, IOException {
        Mockito.when(entityCertificatePersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        tDPSPersistenceHandler.updateEntityData(entityName, EntityType.CA_ENTITY, false);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(entityName)).thenReturn(cAEntityData);
        tDPSPersistenceHandler.updateCertificateData(EntityType.CA_ENTITY, entityName, "issuerdfddg", "seriaalsfgsdfg", false);
    }

    @Test
    public void updateCertificateEntityData() throws EntityNotFoundException, PersistenceException, CertificateException, IOException {
        CAEntityData caEntityData = getCAEntityData();

        CertificateData certificateData = getCertificateData(caEntityData);

        CertificateAuthorityData authorityData = getCertificateAuthorityData(caEntityData);
        caEntityData.setCertificateAuthorityData(authorityData);
        Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(certificateData);
        Mockito.when(entityCertificatePersistenceHelper.getEntityData(entityName)).thenReturn(entityData);

        Mockito.when(persistenceManager.findEntityByName(EntityData.class, entityName, Constants.ENTITY_NAME_PATH)).thenReturn(entityData);
        Mockito.when(entityData.getEntityInfoData()).thenReturn(entityInfoData);
        Mockito.when(entityInfoData.getCertificateDatas()).thenReturn(certificateDatas);

        Mockito.when(cAEntityData.getCertificateAuthorityData()).thenReturn(authorityData);
        tDPSPersistenceHandler.updateCertificateData(EntityType.ENTITY, entityName, "issuerName", "serialnumber", false);
    }

    @Test
    public void getPublishedCertificatesList() throws CertificateException, PersistenceException, IOException {

        tDPSPersistenceHandler.getPublishedCertificates(EntityType.ENTITY, CertificateStatus.ACTIVE);
    }

    @Test
    public void getPublishedCertificatesListforCA() throws CertificateException, PersistenceException, IOException {

        tDPSPersistenceHandler.getPublishedCertificates(EntityType.CA_ENTITY, CertificateStatus.ACTIVE);
    }

    @Test
    public void getPublishedCertificatesListforCAEntity() throws CertificateException, PersistenceException, IOException {
        List<CAEntityData> caEntityDatas = new ArrayList<CAEntityData>();
        CAEntityData caEntityData = getCAEntityData();
        CertificateAuthorityData certificateAuthorityData = getCertificateAuthorityData(caEntityData);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityDatas.add(caEntityData);
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("publishCertificatetoTDPS", true);
        Mockito.when(persistenceManager.findEntitiesWhere(CAEntityData.class, parameters)).thenReturn(caEntityDatas);
        entityName = "Name";

        CertificateData certificateData = getCertificateData(caEntityData);

        List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
        certificateDatas.add(certificateData);

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(entityName)).thenReturn(caEntityData);
        final CertificateStatus certificateStatuses = CertificateStatus.ACTIVE;
        Mockito.when(caCertificatePersistenceHelper.getCertificateDatas(entityName, certificateStatuses)).thenReturn(certificateDatas);
        tDPSPersistenceHandler.getPublishedCertificates(EntityType.CA_ENTITY, CertificateStatus.ACTIVE);
    }

    private CertificateAuthorityData getCertificateAuthorityData(CAEntityData caEntityData) {
        CertificateAuthorityData authorityData = new CertificateAuthorityData();
        authorityData.setName("Name");
        authorityData.setIssuer(caEntityData);

        return authorityData;
    }

    private CertificateData getCertificateData(final CAEntityData caEntityData) {
        CertificateData certificateData = new CertificateData();
        certificateData.setCertificate(new byte[] { 1, 2, 2 });
        certificateData.setId(1);
        certificateData.setPublishedToTDPS(true);
        certificateData.setIssuerCA(cAEntityData);
        return certificateData;
    }

    private CAEntityData getCAEntityData() {
        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setPublishCertificatetoTDPS(false);
        caEntityData.setExternalCA(false);
        return caEntityData;
    }
}
