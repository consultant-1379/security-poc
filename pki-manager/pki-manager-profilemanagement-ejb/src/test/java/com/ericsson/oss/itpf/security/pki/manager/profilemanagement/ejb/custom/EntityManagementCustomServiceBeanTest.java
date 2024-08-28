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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb.custom;

import static org.junit.Assert.assertNotNull;

import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementCustomServiceBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityManagementCustomServiceBean.class);

    @InjectMocks
    EntityManagementCustomServiceBean entityManagementCustomServiceBean;

    @Mock
    private EntitiesManager entitiesManager;

    @Test
    public void testEmCustomServiceBean() {

        final EntityCategory[] entityCategories = new EntityCategory[5];
        final List<Entity> entities = new ArrayList<Entity>();

        Mockito.when(entitiesManager.getEntitiesWithInvalidCertificate(new Date(), 10, entityCategories)).thenReturn(entities);
        entityManagementCustomServiceBean.getEntitiesWithInvalidCertificate(new Date(), 10, entityCategories);
        assertNotNull(entities);
    }

}
