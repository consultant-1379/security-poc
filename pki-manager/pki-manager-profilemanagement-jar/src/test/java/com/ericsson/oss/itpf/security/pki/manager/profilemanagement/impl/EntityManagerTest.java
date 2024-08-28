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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.persistence.PersistenceException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAHierarchyPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityDetailsPeristenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPCountException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.utils.EnrollmentInformationHandler;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.validator.BasicValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityManagerTest {

    @Mock
    Logger logger;
    @InjectMocks
    EntitiesManager entityManager;

    @Mock
    BasicValidator entityValidator;

    @Mock
    CoreEntitiesManager coreEntitiesManager;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    EntityPersistenceHandler entityPersistenceHandler;

    @Mock
    EnrollmentInformationHandler enrollmentInformationHandler;

    @Mock
    PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Mock
    CAHierarchyPersistenceHandler cAHeirarchyPersistenceHandler;

    @Mock
    ModelMapper entityMapper;

    @Mock
    TDPSPersistenceHandler tDPSPersistenceHandler;

    @Mock
    EntityDetailsPeristenceHandler entityDetailsPeristenceHandler;

    @Mock
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    ModelMapperv1 entityMapperv1;

    EnrollmentInfo enrollmentInfo;

    Entity entity;
    CAEntity caEntity;
    Entities entities = new Entities();
    List<Entity> entityList;

    List<CAEntity> caEntityList;

    private Certificate certificate;
    Map<String, List<Certificate>> certificateInfoMap = new HashMap<String, List<Certificate>>();
    List<Certificate> certificates = new ArrayList<Certificate>();

    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);
        certificate = prepareActiveCertificate();

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);

    }

    @Test
    public void testcreateEntity() {

        when(entitiesPersistenceHandler.createEntity(entity)).thenReturn(entity);

        doNothing().when(coreEntitiesManager).createEntity(entity);

        assertEquals(entityManager.createEntity(entity), entity);

    }

    @Test
    public void testGetEntities() {

        when(entitiesPersistenceHandler.getEntities(EntityType.ENTITY)).thenReturn(entities);

        assertEquals(entityManager.getEntities(EntityType.ENTITY), entities);

    }

    @Test
    public void testGetEntitiesWithCA_ENTITY() {
        final Entities entities = new Entities();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);
        entities.setCAEntities(caEntityList);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);
        when(entitiesPersistenceHandler.getEntities(EntityType.CA_ENTITY)).thenReturn(entities);
        assertEquals(entityManager.getEntities(EntityType.CA_ENTITY), entities);

    }

    @Test
    public void testGetEntity() {

        when(entitiesPersistenceHandler.getEntity(entity)).thenReturn(entity);

        assertEquals(entityManager.getEntity(entity), entity);

    }

    @Test
    public void testUpdateEntity() {

        when(entitiesPersistenceHandler.updateEntity(entity)).thenReturn(entity);

        doNothing().when(coreEntitiesManager).updateEntity(entity);

        assertEquals(entityManager.updateEntity(entity), entity);

    }

    @Test
    public void testDeletetEntity() {

        when(entitiesPersistenceHandler.isDeletable(entity)).thenReturn(true);

        doNothing().when(coreEntitiesManager).deleteEntity(entity);

        doNothing().when(entitiesPersistenceHandler).deleteEntity(entity);

        entityManager.deleteEntity(entity);

        verify(entitiesPersistenceHandler).deleteEntity(entity);

        verify(coreEntitiesManager).deleteEntity(entity);

    }

    @Test
    public void testIsNameAvailableTrue() {

        when(entitiesPersistenceHandler.isNameAvailable(entity.getEntityInfo().getName())).thenReturn(true);

        assertTrue(entityManager.isNameAvailable(entity.getEntityInfo().getName(), EntityType.ENTITY));

    }

    @Test
    public void testIsNameAvailableFalse() {

        when(entitiesPersistenceHandler.isNameAvailable(entity.getEntityInfo().getName())).thenReturn(false);

        assertFalse(entityManager.isNameAvailable(entity.getEntityInfo().getName(), EntityType.ENTITY));

    }

    /**
     * This test case is used to test the valid scenario of getEnrollmentInfo
     */
    @Test
    public void testgetEnrollmentInfoForEntity() {

        when(entitiesPersistenceHandler.getEntity(entity)).thenReturn(entity);

    }

    /**
     * This test case is used to check if getEnrollmentInfo method throws OTPExpiredException when Invalid entity count is set to the entity.
     */
    @Test(expected = OTPExpiredException.class)
    public void testGetEnrollmentInfoForEntityForOTPExpiredException() {

        entity.getEntityInfo().setOTPCount(0);
        when(entitiesPersistenceHandler.getEntity(entity)).thenReturn(entity);
        entityManager.getEnrollmentInfoForEntity(entity, EnrollmentType.cmp);
        verify(entitiesPersistenceHandlerFactory).getEntitiesPersistenceHandler(EntityType.ENTITY);

    }

    /**
     * This test case is used to test the valid scenario of getOTP.
     */
    @Test
    public void testGetOTP() {
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        entityManager.getOtp(entity);
        verify(entitiesPersistenceHandlerFactory).getEntitiesPersistenceHandler(EntityType.ENTITY);
        assertEquals(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY), entityPersistenceHandler);
    }

    @Test
    public void testUpdateEntities() {

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        when(entitiesPersistenceHandler.updateEntity(entities.getEntities().get(0))).thenReturn(entity);

        entityManager.updateEntities(entities);
        verify(logger).debug("Entities Updated {}", entities);

    }

    @Test
    public void testUpdateEntitiesForCAEntity() {
        final Entities entities = new Entities();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);
        entities.setCAEntities(caEntityList);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);
        when(entitiesPersistenceHandler.updateEntity(caEntity)).thenReturn(caEntity);

        entityManager.updateEntities(entities);
        verify(logger).debug("Entities Updated {}", entities);

    }

    @Test
    public void testDeleteEntites() {
        entityManager.deleteEntites(entities);
        verify(logger).debug("Entities Deleted");

    }

    @Test
    public void testDeleteEntitesForCAEntity() {
        final Entities entities = new Entities();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);
        entities.setCAEntities(caEntityList);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);

        entityManager.deleteEntites(entities);
        verify(logger).debug("Entities Deleted");

    }

    @Test
    public void testGetEntitiesByCategory() {
        final EntityCategory entityCategory = new EntityCategory();

        final List<Entity> entityList = new ArrayList<Entity>();
        assertEquals(entityList, entityManager.getEntitiesByCategory(entityCategory, true));

    }

    @Test
    public void testGetEntityNameListByIssuerName() {
        final String caName = "caName";
        final List<String> entityNameList = new ArrayList<String>();
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        assertEquals(entityNameList, entityManager.getEntityNameListByIssuerName(caName));

    }

    @Test
    public void testGetEntityNameListBYIssuerNameThrowsPersistenceException() {
        final String caName = "caName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(PersistenceException.class).when(entityPersistenceHandler).getEntityNameListByCaName(caName);
        try {
            entityManager.getEntityNameListByIssuerName(caName);
        } catch (final EntityServiceException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameListBYIssuerNameThrowsCANotFoundException() {
        final String caName = "caName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(CANotFoundException.class).when(entityPersistenceHandler).getEntityNameListByCaName(caName);
        try {
            entityManager.getEntityNameListByIssuerName(caName);
        } catch (final CANotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameListBYIssuerNameThrowsException() {
        final String caName = "caName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(CANotFoundException.class).when(entityPersistenceHandler).getEntityNameListByCaName(caName);
        try {
            entityManager.getEntityNameListByIssuerName(caName);
        } catch (final CANotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameListByTrustProfileName() {
        final String trustProfileName = "trustProfileName";
        final List<String> entityNameList = new ArrayList<String>();
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        assertEquals(entityNameList, entityManager.getEntityNameListByTrustProfileName(trustProfileName));
    }

    @Test
    public void testGetEntityNameListByTrustProfileNameThrowsPersistenceException() {
        final String trustProfileName = "trustProfileName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(PersistenceException.class).when(entityPersistenceHandler).getEntityNameListByTrustProfile(trustProfileName);
        try {
            entityManager.getEntityNameListByTrustProfileName(trustProfileName);
        } catch (final EntityServiceException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameListByTrustProfileNameThrowsProfileNotFoundException() {
        final String trustProfileName = "trustProfileName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(ProfileNotFoundException.class).when(entityPersistenceHandler).getEntityNameListByTrustProfile(trustProfileName);
        try {
            entityManager.getEntityNameListByTrustProfileName(trustProfileName);
        } catch (final ProfileNotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameListByTrustProfileNameThrowsException() {
        final String trustProfileName = "trustProfileName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(ProfileNotFoundException.class).when(entityPersistenceHandler).getEntityNameListByTrustProfile(trustProfileName);
        try {
            entityManager.getEntityNameListByTrustProfileName(trustProfileName);
        } catch (final ProfileNotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameByCaNameAndSerialNumber() {
        final String caName = "caName";
        final String serialNumber = "serialNumber";
        final String entityName = "entityName";
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        when(entityPersistenceHandler.getEntityNameByCaNameAndSerialNumber(caName, serialNumber)).thenReturn(entityName);
        Assert.assertEquals(entityName, entityManager.getEntityNameByCaNameAndSerialNumber(caName, serialNumber));

    }

    @Test
    public void testGetEntityNameByCaNameAndSerialNumberThrowsPersistenceException() {
        final String caName = "caName";
        final String serialNumber = "serialNumber";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(PersistenceException.class).when(entityPersistenceHandler).getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        try {
            entityManager.getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        } catch (final EntityServiceException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameByCaNameAndSerialNumberThrowsSerialNumberNotFoundException() {
        final String caName = "caName";
        final String serialNumber = "serialNumber";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(SerialNumberNotFoundException.class).when(entityPersistenceHandler).getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        try {
            entityManager.getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        } catch (final SerialNumberNotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameByCaNameAndSerialNumberThrowsCANotFoundException() {
        final String caName = "caName";
        final String serialNumber = "serialNumber";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(CANotFoundException.class).when(entityPersistenceHandler).getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        try {
            entityManager.getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        } catch (final CANotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityNameByCaNameAndSerialNumberThrowsException() {
        final String caName = "caName";
        final String serialNumber = "serialNumber";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(SerialNumberNotFoundException.class).when(entityPersistenceHandler).getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        try {
            entityManager.getEntityNameByCaNameAndSerialNumber(caName, serialNumber);
        } catch (final SerialNumberNotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEntityListByIssuerName() {
        final String caName = "caName";
        final List<Entity> entityList = new ArrayList<Entity>();
        final List<EntityData> entityDataList = new ArrayList<EntityData>();
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        when(entityPersistenceHandler.loadEntityListByCaName(caName)).thenReturn(entityDataList);
        Assert.assertEquals(entityList, entityManager.getEntityListByIssuerName(caName));
    }

    @Test
    public void testGetEntityListByIssuerNameThrowsPersistenceException() {
        final String caName = "caName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(PersistenceException.class).when(entityPersistenceHandler).loadEntityListByCaName(caName);
        try {
            entityManager.getEntityListByIssuerName(caName);
        } catch (final EntityServiceException e) {
            result = true;
        }
        Assert.assertTrue(result);

    }

    @Test
    public void testGetEntityListByIssuerNameThrowsCANotFoundException() {
        final String caName = "caName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(CANotFoundException.class).when(entityPersistenceHandler).loadEntityListByCaName(caName);
        try {
            entityManager.getEntityListByIssuerName(caName);
        } catch (final CANotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);

    }

    @Test
    public void testGetEntityListByIssuerNameThrowsException() {
        final String caName = "caName";
        boolean result = false;
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        doThrow(CANotFoundException.class).when(entityPersistenceHandler).loadEntityListByCaName(caName);
        try {
            entityManager.getEntityListByIssuerName(caName);
        } catch (final CANotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);

    }

    @Test
    public void testGetEnrollmentInfoForEntitythrowsException() {
        boolean result = false;
        try {
            entityManager.getEnrollmentInfoForEntity(entity, EnrollmentType.cmp);
        } catch (final EntityNotFoundException e) {
            result = true;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testGetEnrollmentInfoForEntity() {
        final EnrollmentInfo enrollmentInfo = new EnrollmentInfo();
        when(entitiesPersistenceHandler.getEntities(EntityType.ENTITY)).thenReturn(entities);
        when(entitiesPersistenceHandler.getEntity(entity)).thenReturn(entity);
        when(enrollmentInformationHandler.getEnrollmentInformation(entity, EnrollmentType.cmp)).thenReturn(enrollmentInfo);
        Assert.assertEquals(enrollmentInfo, entityManager.getEnrollmentInfoForEntity(entity, EnrollmentType.cmp));

    }

    @Test
    public void testUpdateOTP() {
        entity.getEntityInfo().setOTP("oTP");
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        entityManager.updateOTP(entity);
        verify(logger).info("OTP is updated");
    }

    @Test(expected = InvalidOTPCountException.class)
    public void testUpdateOTPWhenOtpCountzero() {
        entity.getEntityInfo().setOTP("oTP");
        entity.getEntityInfo().setOTPCount(0);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        entityManager.updateOTP(entity);

    }

    @Test
    public void testUpdateOTPWhenOtpEmptyStringAndOtpCountZero() {
        entity.getEntityInfo().setOTP("");
        entity.getEntityInfo().setOTPCount(0);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        entityManager.updateOTP(entity);
        verify(logger).info("OTP is Disabled");

    }

    @Test(expected = InvalidOTPCountException.class)
    public void testUpdateOTPWhenOtpCountGreaterThanFive() {
        entity.getEntityInfo().setOTP("oTP");
        entity.getEntityInfo().setOTPCount(6);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        entityManager.updateOTP(entity);

    }

    @Test(expected = TrustDistributionPointURLNotFoundException.class)
    public void testGetTrustDistributionPointUrlWhenHostNull() {
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn(null);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn(null);
        entityManager.getTrustDistributionPointUrl(entity, "issuer_123", CertificateStatus.ACTIVE);
    }

    @Test
    public void testGetTrustDistributionPointUrl() {
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("host");
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("host");
        entityManager.getTrustDistributionPointUrl(entity, "issuer_123", CertificateStatus.ACTIVE);

    }

    @Test(expected = TrustDistributionPointURLNotFoundException.class)
    public void testGetTrustDistributionPointUrlsWhenHostNull() {
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn(null);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn(null);
        entityManager.getTrustDistributionPointUrls(entity, "issuer_123", CertificateStatus.ACTIVE);
    }

    @Test
    public void testGetTrustDistributionPointUrls() {
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("host");
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("host");
        entityManager.getTrustDistributionPointUrls(entity, "issuer_123", CertificateStatus.ACTIVE);

    }

    @Test
    public void testGetTrustDistributionPointInfosByTypeAndStatus() throws EntityServiceException, EntityNotFoundException, CertificateException, PersistenceException, IOException {
        final EntityType entityType = EntityType.CA_ENTITY;
        final CertificateStatus status = CertificateStatus.ACTIVE;
        certificates.add(certificate);
        certificateInfoMap.put("status", certificates);
        Mockito.when(tDPSPersistenceHandler.getPublishedCertificates(entityType, status)).thenReturn(certificateInfoMap);
        Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("dnsname:");
        Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("dnsname:");
        entityManager.getTrustedEntityInfosByTypeAndStatus(entityType, status);
        Mockito.verify(pkiManagerConfigurationListener).getSbLoadBalancerIPv4Address();
    }

    @Test
    public void testGetTrustDistributionPointInfosByTypeAndStatusNull() throws EntityServiceException, EntityNotFoundException, CertificateException, PersistenceException, IOException {
        final EntityType entityType = EntityType.CA_ENTITY;
        final CertificateStatus status = CertificateStatus.ACTIVE;
        Mockito.when(tDPSPersistenceHandler.getPublishedCertificates(entityType, status)).thenReturn(certificateInfoMap);
        entityManager.getTrustedEntityInfosByTypeAndStatus(entityType, status);
        Mockito.verify(tDPSPersistenceHandler).getPublishedCertificates(entityType, status);

    }

    @Test
    public void testvalidateAndcreateCoreEntities() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        doNothing().when(coreEntitiesManager).createBulkEntities(entityList);

        entityManager.validateAndcreateCoreEntities(entityList);
    }

    @Test
    public void testpersistEntityData() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);

        when(entityPersistenceHandler.persistEntityData(entityDataList1.get(0))).thenReturn(entityDataList1.get(0));

        entityManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY);
    }

    private Certificate prepareActiveCertificate() {
        final Certificate certificate = new Certificate();
        certificate.setId(10101);

        final Subject subject = new Subject();
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setIssuer(prepareCertificateAuthority());
        certificate.setSubject(subject);
        return certificate;
    }

    private CertificateAuthority prepareCertificateAuthority() {

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(101);
        certificateAuthority.setName("ENMCA");
        certificateAuthority.setRootCA(false);

        return certificateAuthority;
    }

    @Test
    public void testGetEntitiesByStatus() {
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);
        entityManager.getEntitiesByStatus(EntityType.ENTITY, 1);
        Mockito.verify(entitiesPersistenceHandlerFactory).getEntitiesPersistenceHandler(EntityType.ENTITY);

    }

    @Test
    public void testGetEntitiesWithInvalidCertificate() {
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);

        entityManager.getEntitiesWithInvalidCertificate(new Date("10/2/2016"), 3);
        Mockito.verify(entityPersistenceHandler).getEntitiesWithInvalidCertificate(new Date("10/2/2016"), 3);

    }

    @Test
    public void testGetCAHierarchies() {
        entityManager.getCAHierarchies();
        Mockito.verify(cAHeirarchyPersistenceHandler).getRootCAHierarchies();

    }

    @Test
    public void testGetCAHierarchyByName() {
        entityManager.getCAHierarchyByName("Entity_Test");
        Mockito.verify(cAHeirarchyPersistenceHandler).getCAHierarchyByName("Entity_Test");
    }

    @Test
    public void testGetEntitiesCountByFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();
        final List<EntityType> entityTypes = new ArrayList<EntityType>();
        entityTypes.add(EntityType.ENTITY);
        entitiesFilter.setType(entityTypes);
        entitiesFilter.setName("");

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY).getEntitiesCountByFilter(entitiesFilter)).thenReturn(9);
        final int count = entityManager.getEntitiesCountByFilter(entitiesFilter);
        assertEquals(9, count);
    }

    @Test
    public void testGetEntityDetailsByFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();
        final List<EntityType> entityTypes = new ArrayList<EntityType>();
        entityTypes.add(EntityType.ENTITY);
        entitiesFilter.setType(entityTypes);
        entitiesFilter.setName("");

        entityManager.getEntityDetailsByFilter(entitiesFilter);
        Mockito.verify(entityDetailsPeristenceHandler).getEntityDetails(entitiesFilter);
    }

    @Test
    public void testGetTrustProfileNamesByExtCA() {
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(caEntityPersistenceHandler);
        entityManager.getTrustProfileNamesByExtCA(entitiesSetUpData.getCaEntityData());

        Mockito.verify(caEntityPersistenceHandler).getTrustProfileNamesWithUseAsExternalCAs(entitiesSetUpData.getCaEntityData());

    }

    @Test
    public void testGetCertificateSerialNumber() {
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        final CertificateData certificateData = new CertificateData();
        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("issuer_123");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        certificateData.setIssuerCA(caEntityData);
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        certificateDatas.add(certificateData);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("125.9.0.1");
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("125.9.0.1");
        when(tDPSPersistenceHandler.getCertificateDatas(entity)).thenReturn(certificateDatas);
        entityManager.getTrustDistributionPointUrl(entity, "issuer_123", CertificateStatus.ACTIVE);
        Mockito.verify(tDPSPersistenceHandler).getCertificateDatas(entity);

    }

    @Test(expected = TrustDistributionPointURLNotFoundException.class)
    public void testGetCertificateSerialNumberAsValueNull() {
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("125.9.0.1");
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("126.9.0.1.a");
        when(tDPSPersistenceHandler.getCertificateDatas(entity)).thenReturn(null);
        entityManager.getTrustDistributionPointUrl(entity, "issuer_123", CertificateStatus.ACTIVE);
    }

}
