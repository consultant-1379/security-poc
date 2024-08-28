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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;


import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.CAEntityManagementService;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.eservice.ProflieManagementEserviceProxy;

@RunWith(MockitoJUnitRunner.class)
public class CoreEntitiesManagerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CoreEntitiesManager.class);

    @InjectMocks
    CoreEntitiesManager coreEntitiesManager;

    @Mock
    CAEntityManagementService caEntityManagementService;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    ProflieManagementEserviceProxy proflieManagementEserviceProxy;

    Entity entity;
    CAEntity caEntity;
    Entities entities = new Entities();
    List<Entity> entityList;
    List<CAEntity> caEntityList;

    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);
        caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);

        Mockito.when(proflieManagementEserviceProxy.getEntityManagementService()).thenReturn(entityManagementService);
        Mockito.when(proflieManagementEserviceProxy.getCaEntityManagementService()).thenReturn(caEntityManagementService);

    }

    @Test
    public void testcreateEntity() {

        when(entityManagementService.createEntity(entity.getEntityInfo())).thenReturn(entity.getEntityInfo());
        coreEntitiesManager.createEntity(entity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException.class)
    public void testcreateEntityThrowsException() {

        when(entityManagementService.createEntity(entity.getEntityInfo())).thenThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException.class);
        coreEntitiesManager.createEntity(entity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException.class)
    public void testcreateEntityThrowsEntityServiceException() {

        when(entityManagementService.createEntity(entity.getEntityInfo())).thenThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException.class);
        coreEntitiesManager.createEntity(entity);
    }

    @Test
    public void testcreateCAEntity() {

        when(caEntityManagementService.createCA(caEntity.getCertificateAuthority())).thenReturn(caEntity.getCertificateAuthority());
        coreEntitiesManager.createEntity(caEntity);
    }

    @Test
    public void testupdateEntity() {

        when(entityManagementService.updateEntity(entity.getEntityInfo())).thenReturn(entity.getEntityInfo());
        coreEntitiesManager.updateEntity(entity);
    }

    @Test
    public void testupdateCAEntity() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        final List<CAEntity> caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);

        when(caEntityManagementService.updateCA(caEntity.getCertificateAuthority())).thenReturn(caEntity.getCertificateAuthority());
        coreEntitiesManager.updateEntity(caEntity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testupdateEntityThrowsException() {

        when(entityManagementService.updateEntity(entity.getEntityInfo())).thenThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException.class);
        coreEntitiesManager.updateEntity(entity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException.class)
    public void testupdateEntityThrowsEntityServiceException() {

        when(entityManagementService.updateEntity(entity.getEntityInfo())).thenThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException.class);
        coreEntitiesManager.updateEntity(entity);
    }

    @Test
    public void testdeleteEntity() {

        when(entityManagementService.updateEntity(entity.getEntityInfo())).thenReturn(entity.getEntityInfo());
        coreEntitiesManager.deleteEntity(entity);
    }

    @Test
    public void testdeleteCAEntity() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        final List<CAEntity> caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);

        doNothing().when(caEntityManagementService).deleteCA(caEntity.getCertificateAuthority());
        coreEntitiesManager.deleteEntity(caEntity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testdeleteEntityThrowsException() {

        doThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException.class).when(entityManagementService).deleteEntity(entity.getEntityInfo());
        coreEntitiesManager.deleteEntity(entity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException.class)
    public void testdeleteEntityThrowsNameinUseException() {

        doThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityInUseException.class).when(entityManagementService).deleteEntity(entity.getEntityInfo());
        coreEntitiesManager.deleteEntity(entity);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException.class)
    public void testdeleteEntityThrowsEntityServiceException() {

        doThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException.class).when(entityManagementService).deleteEntity(entity.getEntityInfo());
        coreEntitiesManager.deleteEntity(entity);
    }

    @Test
    public void testCreateBulkEntitiesForEntityList() {
        coreEntitiesManager.createBulkEntities(entityList);
        final List<EntityInfo> entitiesInfo = new ArrayList<EntityInfo>();
        entitiesInfo.add(entity.getEntityInfo());
        Mockito.verify(entityManagementService).importEntities(entitiesInfo);
    }

    @Test
    public void testCreateBulkEntitiesForCAEntityList() {
        coreEntitiesManager.createBulkEntities(caEntityList);
        final List<CertificateAuthority> certificateAuthorities = new ArrayList<CertificateAuthority>();
        certificateAuthorities.add(caEntity.getCertificateAuthority());
        Mockito.verify(caEntityManagementService).importCAEntities(certificateAuthorities);
    }

    @Test(expected = EntityAlreadyExistsException.class)
    public void testCreateBulkEntitiesWithEntityException() {

        final List<CertificateAuthority> certificateAuthorities = new ArrayList<CertificateAuthority>();
        certificateAuthorities.add(caEntity.getCertificateAuthority());
        doThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException.class).when(caEntityManagementService).importCAEntities(certificateAuthorities);

        coreEntitiesManager.createBulkEntities(caEntityList);

    }

    @Test(expected = EntityServiceException.class)
    public void testCreateBulkEntitiesWithServiceException() {
        final List<EntityInfo> entitiesInfo = new ArrayList<EntityInfo>();
        entitiesInfo.add(entity.getEntityInfo());
        doThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException.class).when(entityManagementService).importEntities(entitiesInfo);

        coreEntitiesManager.createBulkEntities(entityList);

    }

}
