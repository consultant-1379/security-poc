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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.EntityManager;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementServiceBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityManagementServiceBean.class);

    @InjectMocks
    EntityManagementServiceBean entityManagementServiceBean;

    @Mock
    EntityManager entitiesManager;

    EntityInfo entityInfo = new EntityInfo();

    @Before
    public void setup() {

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setId(1);
        entityInfo.setName("ENMService1");
    }

    @Test
    public void testCreateEntity() {

        when(entitiesManager.createEntity(entityInfo)).thenReturn(entityInfo);

        assertEquals(entityInfo, entityManagementServiceBean.createEntity(entityInfo));
    }

    @Test(expected = NullPointerException.class)
    public void testCreateNull() {

        entityManagementServiceBean.createEntity(null);
    }

    @Test
    public void testUpdateEntity() {

        when(entitiesManager.updateEntity(entityInfo)).thenReturn(entityInfo);

        assertEquals(entityInfo, entityManagementServiceBean.updateEntity(entityInfo));
    }

    @Test(expected = NullPointerException.class)
    public void testUpdateNull() {

        entityManagementServiceBean.updateEntity(null);
    }

    @Test
    public void testDeteleEntity() {

        entityManagementServiceBean.deleteEntity(entityInfo);
        verify(entitiesManager).deleteEntity(entityInfo);
    }

    @Test(expected = NullPointerException.class)
    public void testDeleteEntityNull() {

        entityManagementServiceBean.deleteEntity(null);
    }

}
