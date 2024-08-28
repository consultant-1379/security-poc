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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl;

import java.security.cert.CertificateException;

import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.EntityValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagerTest {

    @Spy
    final private Logger logger = LoggerFactory.getLogger(EntityManager.class);

    @InjectMocks
    EntityManager entityManager;

    @Mock
    EntityPersistenceHandler entityPersistenceHandler;

    @Spy
    EntityValidator entityValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityModelMapper entityMapper;
    @Mock
    Query query;

    @Mock
    SystemRecorder systemRecorder;

    EntityInfo entityInfo;

    EntityInfoData entityInfoData;

    @Before
    public void setUp() throws Exception {
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entityInfo = entitiesSetUpData.getEntityInfo();
        entityInfo.setName("ERBS_1");
        entityInfo.setId(1L);
        entityInfoData = entitiesSetUpData.getEntityInfoData();
    }

    @Test
    public void testCreateEntity() throws CertificateException {
        Mockito.doNothing().when(entityValidator).validateEntity(entityInfo, OperationType.CREATE);
        Mockito.doNothing().when(entityPersistenceHandler).persistEntity(entityInfo);
        Mockito.when(persistenceManager.findEntityByName(EntityInfoData.class, entityInfo.getName(), "name")).thenReturn(entityInfoData);
        Mockito.when(entityMapper.toAPIFromModel(entityInfoData)).thenReturn(entityInfo);
        entityManager.createEntity(entityInfo);
    }

    @Test
    public void testUpdateEntity() throws CertificateException {

        Mockito.when(persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId())).thenReturn(entityInfoData);
        Mockito.doNothing().when(entityValidator).validateEntity(entityInfo, OperationType.UPDATE);
        Mockito.doNothing().when(entityPersistenceHandler).updateEntity(entityInfo);
        Mockito.when(persistenceManager.findEntityByName(EntityInfoData.class, entityInfo.getName(), "name")).thenReturn(entityInfoData);
        Mockito.doNothing().when(entityPersistenceHandler).updateCertificateStatus(entityInfoData, entityInfo.getStatus());

        Mockito.when(entityMapper.toAPIFromModel(entityInfoData)).thenReturn(entityInfo);
        entityManager.updateEntity(entityInfo);
    }

    @Test
    public void testDeleteEntity() {
        Mockito.doNothing().when(entityValidator).checkEntityNameFormat(entityInfo.getName());
        Mockito.when(entityPersistenceHandler.getEntityInfoData(entityInfo)).thenReturn(entityInfoData);
        entityManager.deleteEntity(entityInfo);
    }

    @Test
    public void testDeleteEntityNewStatus() {
        entityInfoData.setStatus(EntityStatus.NEW);
        Mockito.doNothing().when(entityValidator).checkEntityNameFormat(entityInfo.getName());
        Mockito.when(entityPersistenceHandler.getEntityInfoData(entityInfo)).thenReturn(entityInfoData);
        entityManager.deleteEntity(entityInfo);
    }

    @Test
    public void testDeleteEntityInactiveStatus() {
        entityInfoData.setStatus(EntityStatus.INACTIVE);
        Mockito.doNothing().when(entityValidator).checkEntityNameFormat(entityInfo.getName());
        Mockito.when(entityPersistenceHandler.getEntityInfoData(entityInfo)).thenReturn(entityInfoData);
        entityManager.deleteEntity(entityInfo);
    }

    @Test
    public void testDeleteEntityInactiveStatus_EntityServiceException() {
        entityInfoData.setStatus(EntityStatus.INACTIVE);
        Mockito.doNothing().when(entityValidator).checkEntityNameFormat(entityInfo.getName());
        Mockito.when(entityPersistenceHandler.getEntityInfoData(entityInfo)).thenReturn(entityInfoData);
        Mockito.doThrow(new CoreEntityServiceException()).when(entityPersistenceHandler).updateEntity(entityInfo);
        entityManager.deleteEntity(entityInfo);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testValidateCreate_CoreEntityServiceException() {
        Mockito.doNothing().when(entityValidator).validateEntity(entityInfo, OperationType.CREATE);
        Mockito.doNothing().when(entityPersistenceHandler).persistEntity(entityInfo);
        Mockito.when(persistenceManager.findEntityByName(EntityInfoData.class, entityInfo.getName(), "name")).thenThrow(new PersistenceException());
        Mockito.when(entityMapper.toAPIFromModel(entityInfoData)).thenReturn(entityInfo);
        entityManager.createEntity(entityInfo);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntity_CoreEntityServiceException() {

        Mockito.when(persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId())).thenReturn(entityInfoData);
        Mockito.doNothing().when(entityValidator).validateEntity(entityInfo, OperationType.UPDATE);
        Mockito.doNothing().when(entityPersistenceHandler).updateEntity(entityInfo);
        Mockito.when(persistenceManager.findEntityByName(EntityInfoData.class, entityInfo.getName(), "name")).thenThrow(new PersistenceException());
        Mockito.doNothing().when(entityPersistenceHandler).updateCertificateStatus(entityInfoData, entityInfo.getStatus());

        Mockito.when(entityMapper.toAPIFromModel(entityInfoData)).thenReturn(entityInfo);
        entityManager.updateEntity(entityInfo);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntity_ServiceException() throws CertificateException {

        Mockito.when(persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId())).thenThrow(new PersistenceException());

        entityManager.updateEntity(entityInfo);
    }
}
