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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Date;

import javax.persistence.PersistenceException;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.xml.datatype.DatatypeFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;

@RunWith(MockitoJUnitRunner.class)
public class EntityMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityMapper.class);

    @InjectMocks
    EntityMapper entityMapper;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    EntityCategoryMapper entityCategoryMapper;

    @Mock
    EntityProfileMapper entityProfileMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Mock
    private CRLGenerationInfoMapper cRLGenerationInfoMapper;

    @Mock
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    EntityData entityData;

    Entity entity;

    EntityProfile entityProfile;

    EntityProfileData entityProfileData;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
    Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
    Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet;
    private List<CrlGenerationInfo> crlGenerationInfo = new ArrayList<CrlGenerationInfo>();
    private CertificateData certificateData;
    private EntityInfoData entityInfoData;
    private Certificate certificate;
    private Set<CertificateData> certificateDatas;
    X509Certificate x509Certificate;
    SetUPData setUPData;
    @Before
    public void setup() throws CertificateException, IOException {
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entity = entitiesSetUpData.getEntity();
        entityData = entitiesSetUpData.getEntityData();
        entityProfile = entity.getEntityProfile();
        entityProfileData = entityData.getEntityProfileData();
        certExpiryNotificationDetailsDataSet = entityData.getCertificateExpiryNotificationDetailsData();

        certificate = new Certificate();
        certificate.setId(101);
        certificate.setIssuedTime(new Date());
        certificate.setSerialNumber("10101");
        certificate.setStatus(CertificateStatus.ACTIVE);

        certificateData = new CertificateData();
        certificateData.setSerialNumber("10101");
        certificateData.setStatus(1);
        setUPData = new SetUPData();
        x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");
        certificateData.setCertificate(x509Certificate.getEncoded());

        certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(certificateData);

        entityInfoData = new EntityInfoData();
        entityInfoData.setName("ENMService");
        entityInfoData.setCertificateDatas(certificateDatas);
        entityData.setEntityInfoData(entityInfoData);
    }

    @Test
    public void testToAPIModel() throws Exception {

        certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P30D"));
        certificateExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);
        when(entityProfileMapper.toAPIFromModel(entityData.getEntityProfileData())).thenReturn(entityProfile);
        Mockito.when(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet)).thenReturn(certificateExpiryNotificationDetailsSet);

        final List<CertificateData> certificateDataList = new ArrayList<CertificateData>();
        certificateDataList.add(certificateData);

        Mockito.when(entityCertificatePersistenceHelper.getCertificateDatas(entityInfoData.getName().toString(), CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificateDataList);

        try {
            Mockito.when(cRLGenerationInfoMapper.toAPIFromModel(Mockito.anySet())).thenReturn(crlGenerationInfo);
        } catch (InvalidCRLGenerationInfoException | CertificateException | IOException e) {
            fail(e.getMessage());
        }
        final Entity entity = entityMapper.toAPIFromModel(entityData);

        assertEquals(entity.getEntityInfo().getName(), entityData.getEntityInfoData().getName());

    }

    @Test(expected = NullPointerException.class)
    public void testToAPIModelNull() throws Exception {

        entityMapper.toAPIFromModel(null);

    }

    @Test(expected = NullPointerException.class)
    public void testToAPIModelEmpty() throws Exception {

        entityMapper.toAPIFromModel(new EntityData());

    }

    @Test(expected = ClassCastException.class)
    public void testToAPIModelWrongType() throws Exception {

        entityMapper.toAPIFromModel(new CAEntityData());

    }

    @Test
    public void testFromAPiModel() {

        when(persistenceManager.findEntityByName(EntityProfileData.class, entity.getEntityProfile().getName(), "name")).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenReturn(entityData.getEntityCategoryData());
        final EntityData entityData1 = entityMapper.fromAPIToModel(entity);
        assertEquals(entityData1.getEntityInfoData().getName(), entity.getEntityInfo().getName());

    }

    @Test(expected = EntityServiceException.class)
    public void testFromAPiModelPersistenceException() {

        when(persistenceManager.findEntityByName(EntityProfileData.class, entity.getEntityProfile().getName(), "name")).thenThrow(PersistenceException.class);
        final EntityData entityData1 = entityMapper.fromAPIToModel(entity);
        assertEquals(entityData1.getEntityInfoData().getName(), entity.getEntityInfo().getName());

    }

    @Test(expected = EntityServiceException.class)
    public void testFromAPiModelPersistenceException2() {
        when(persistenceManager.findEntityByName(EntityProfileData.class, entity.getEntityProfile().getName(), "name")).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenThrow(PersistenceException.class);
        final EntityData entityData1 = entityMapper.fromAPIToModel(entity);
        assertEquals(entityData1.getEntityInfoData().getName(), entity.getEntityInfo().getName());

    }

    @Test(expected = NullPointerException.class)
    public void testFromAPiModelNull() throws Exception {

        entityMapper.fromAPIToModel(null);

    }

    @Test(expected = NullPointerException.class)
    public void testFromAPiModelEmpty() throws Exception {

        entityMapper.fromAPIToModel(new Entity());

    }

    @Test(expected = ClassCastException.class)
    public void testFromAPiModelWrongType() throws Exception {

        entityMapper.fromAPIToModel(new CAEntity());

    }

}
