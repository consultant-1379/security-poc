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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.validator.BasicValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CAEntityManagerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntitiesManager.class);

    @InjectMocks
    EntitiesManager entitiesManager;

    @Mock
    BasicValidator entityValidator;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    CoreEntitiesManager coreEntitiesManager;
    
    @Mock
    SystemRecorder systemRecorder;
    
    CAEntity caEntity;

    Entities entities = new Entities();

    List<CAEntity> caEntityList;

    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);

        entities.setCAEntities(caEntityList);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);

    }

    @Test
    public void testcreateEntity() {

        when(entitiesPersistenceHandler.createEntity(caEntity)).thenReturn(caEntity);

        assertEquals(entitiesManager.createEntity(caEntity), caEntity);

    }

    @Test
    public void testgetEntities() {

        when(entitiesPersistenceHandler.getEntities(EntityType.CA_ENTITY)).thenReturn(entities);

        assertEquals(entitiesManager.getEntities(EntityType.CA_ENTITY), entities);

    }

    @Test
    public void testGetEntity() {

        when(entitiesPersistenceHandler.getEntity(caEntity)).thenReturn(caEntity);

        assertEquals(entitiesManager.getEntity(caEntity), caEntity);

    }

    @Test
    public void testUpdateEntity() {

        when(entitiesPersistenceHandler.updateEntity(caEntity)).thenReturn(caEntity);

        assertEquals(entitiesManager.updateEntity(caEntity), caEntity);

    }

    @Test
    public void testDeletetEntity() {

        when(entitiesPersistenceHandler.isDeletable(caEntity)).thenReturn(true);

        doNothing().when(coreEntitiesManager).deleteEntity(caEntity);

        doNothing().when(entitiesPersistenceHandler).deleteEntity(caEntity);

        entitiesManager.deleteEntity(caEntity);

        verify(entitiesPersistenceHandler).deleteEntity(caEntity);

        verify(coreEntitiesManager).deleteEntity(caEntity);

    }

    @Test
    public void testIsNameAvailableTrue() {

        when(entitiesPersistenceHandler.isNameAvailable(caEntity.getCertificateAuthority().getName())).thenReturn(true);

        assertTrue(entitiesManager.isNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY));

    }

    @Test
    public void testIsNameAvailableFalse() {

        when(entitiesPersistenceHandler.isNameAvailable(caEntity.getCertificateAuthority().getName())).thenReturn(false);

        assertFalse(entitiesManager.isNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY));

    }
}
