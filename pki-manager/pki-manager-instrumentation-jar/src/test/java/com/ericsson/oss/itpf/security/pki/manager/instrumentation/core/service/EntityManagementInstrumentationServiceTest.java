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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics.EntityManagementInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementInstrumentationServiceTest {

    @InjectMocks
    EntityManagementInstrumentationService entityManagementInstrumentationService;

    @Mock
    EntityManagementInstrumentationBean entityManagementInstrumentationBean;

    long timeInMillis = System.currentTimeMillis();

    @Test
    public void testCreateMethodInvocations() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setCreateMethodInvocations();
        entityManagementInstrumentationService.setMethodInvocations(MetricType.CREATE);
        Mockito.verify(entityManagementInstrumentationBean).setCreateMethodInvocations();
    }

    @Test
    public void testGetMethodInvocations() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setReadMethodInvocations();
        entityManagementInstrumentationService.setMethodInvocations(MetricType.GET);
        Mockito.verify(entityManagementInstrumentationBean).setReadMethodInvocations();
    }

    @Test
    public void testUpdateMethodInvocations() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setUpdateMethodInvocations();
        entityManagementInstrumentationService.setMethodInvocations(MetricType.UPDATE);
        Mockito.verify(entityManagementInstrumentationBean).setUpdateMethodInvocations();
    }

    @Test
    public void testDeleteMethodInvocations() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setDeleteMethodInvocations();
        entityManagementInstrumentationService.setMethodInvocations(MetricType.DELETE);
        Mockito.verify(entityManagementInstrumentationBean).setDeleteMethodInvocations();
    }

    @Test
    public void testCreateMethodFailures() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setCreateMethodInvocations();
        entityManagementInstrumentationService.setMethodInvocations(MetricType.CREATE);
        Mockito.verify(entityManagementInstrumentationBean).setCreateMethodInvocations();
    }

    @Test
    public void testGetMethodFailures() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setReadMethodFailures();
        entityManagementInstrumentationService.setMethodFailures(MetricType.GET);
        Mockito.verify(entityManagementInstrumentationBean).setReadMethodFailures();
    }

    @Test
    public void testUpdateMethodFailures() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setUpdateMethodFailures();
        entityManagementInstrumentationService.setMethodFailures(MetricType.UPDATE);
        Mockito.verify(entityManagementInstrumentationBean).setUpdateMethodFailures();
    }

    @Test
    public void testDeleteMethodFailures() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setDeleteMethodFailures();
        entityManagementInstrumentationService.setMethodFailures(MetricType.DELETE);
        Mockito.verify(entityManagementInstrumentationBean).setDeleteMethodFailures();
    }

    @Test
    public void testCreateMethodTimeInMillis() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setCreateExecutionTimeTotalMillis(timeInMillis);
        entityManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.CREATE, timeInMillis);
        Mockito.verify(entityManagementInstrumentationBean).setCreateExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testGetMethodTimeInMillis() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setReadExecutionTimeTotalMillis(timeInMillis);
        entityManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.GET, timeInMillis);
        Mockito.verify(entityManagementInstrumentationBean).setReadExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testUpdateMethodTimeInMillis() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setUpdateExecutionTimeTotalMillis(timeInMillis);
        entityManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.UPDATE, timeInMillis);
        Mockito.verify(entityManagementInstrumentationBean).setUpdateExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testDeleteMethodTimeInMillis() {
        Mockito.doNothing().when(entityManagementInstrumentationBean).setDeleteExecutionTimeTotalMillis(timeInMillis);
        entityManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.DELETE, timeInMillis);
        Mockito.verify(entityManagementInstrumentationBean).setDeleteExecutionTimeTotalMillis(timeInMillis);
    }
}