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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.rest.EntityManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntityDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementServiceLocalBeanTest {

    @InjectMocks
    EntityManagementServiceLocalBean entityManagementServiceLocalBean;

    @Mock
    Logger logger;

    @Mock
    EntityManagementAuthorizationHandler entityManagementAuthorizationHandler;

    @Mock
    EntitiesManager entitiesManager;

    /**
     * Method to test getEntitiesCountByFilter() method in positive scenario.
     */
    @Test
    public void testGetEntitiesCountByFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();
        when(entitiesManager.getEntitiesCountByFilter(entitiesFilter)).thenReturn(3);

        final int count = entityManagementServiceLocalBean.getEntitiesCountByFilter(entitiesFilter);

        Assert.assertEquals(count, 3);
    }

    /**
     * Method to test getEntityDetailsByFilter() method in positive scenario.
     */
    @Test
    public void testGetEntityDetailsByFilter() {

        final EntitiesFilter entitiesFilter = new EntitiesFilter();
        final List<AbstractEntityDetails> entityDetails = new ArrayList<AbstractEntityDetails>();

        when(entitiesManager.getEntityDetailsByFilter(entitiesFilter)).thenReturn(entityDetails);

        final List<AbstractEntityDetails> entitiesList = entityManagementServiceLocalBean.getEntityDetailsByFilter(entitiesFilter);

        assertNotNull(entitiesList);
    }

    /**
     * Method to test fetchCAEntitiesIdAndName() method in positive scenario.
     */
    @Test
    public void testFetchCAEntitiesIdAndName() {
        final List<CAEntity> issuersList = new ArrayList<CAEntity>();

        when(entitiesManager.fetchCAEntitiesIdAndName(CAStatus.ACTIVE, false)).thenReturn(issuersList);
        entityManagementServiceLocalBean.fetchCAEntitiesIdAndName(CAStatus.ACTIVE, false);

        assertNotNull(issuersList);
        Mockito.verify(logger).debug("Retrieved list of active CA entities");

    }

    /**
     * Method to test fetchActiveIssuers() method in negative scenario.
     */
    @Test(expected = EntityServiceException.class)
    public void testFetchCAEntitiesIdAndName_EntityServiceException() {
        when(entitiesManager.fetchCAEntitiesIdAndName(CAStatus.ACTIVE, false)).thenThrow(new EntityServiceException());
        entityManagementServiceLocalBean.fetchCAEntitiesIdAndName(CAStatus.ACTIVE, false);

        Mockito.verify(logger).debug("Retrieved list of active CA entities");

    }
}