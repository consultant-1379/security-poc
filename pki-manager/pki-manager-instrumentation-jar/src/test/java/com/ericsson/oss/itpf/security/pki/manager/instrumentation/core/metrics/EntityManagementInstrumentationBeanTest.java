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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementInstrumentationBeanTest {

    @InjectMocks
    EntityManagementInstrumentationBean entityManagementInstrumentationBean;

    /**
     * Method to test Method Invocations count
     */
    @Test
    public void testMethodInvocations() {
        entityManagementInstrumentationBean.setCreateMethodInvocations();
        entityManagementInstrumentationBean.setUpdateMethodInvocations();
        entityManagementInstrumentationBean.setReadMethodInvocations();
        entityManagementInstrumentationBean.setDeleteMethodInvocations();

        entityManagementInstrumentationBean.setCreateMethodInvocations();
        entityManagementInstrumentationBean.setUpdateMethodInvocations();
        entityManagementInstrumentationBean.setReadMethodInvocations();
        entityManagementInstrumentationBean.setDeleteMethodInvocations();

        assertEquals(entityManagementInstrumentationBean.getCreateMethodInvocations(), 2);
        assertEquals(entityManagementInstrumentationBean.getUpdateMethodInvocations(), 2);
        assertEquals(entityManagementInstrumentationBean.getReadMethodInvocations(), 2);
        assertEquals(entityManagementInstrumentationBean.getDeleteMethodInvocations(), 2);
    }

    /**
     * Method to test Method Failures count
     */
    @Test
    public void testMethodFailure() {
        entityManagementInstrumentationBean.setCreateMethodFailures();
        entityManagementInstrumentationBean.setUpdateMethodFailures();
        entityManagementInstrumentationBean.setReadMethodFailures();
        entityManagementInstrumentationBean.setDeleteMethodFailures();

        entityManagementInstrumentationBean.setCreateMethodFailures();
        entityManagementInstrumentationBean.setUpdateMethodFailures();
        entityManagementInstrumentationBean.setReadMethodFailures();
        entityManagementInstrumentationBean.setDeleteMethodFailures();

        assertEquals(entityManagementInstrumentationBean.getCreateMethodFailures(), 2);
        assertEquals(entityManagementInstrumentationBean.getUpdateMethodFailures(), 2);
        assertEquals(entityManagementInstrumentationBean.getReadMethodFailures(), 2);
        assertEquals(entityManagementInstrumentationBean.getDeleteMethodFailures(), 2);
    }

    /**
     * Method to test Method ExecutionTimeTotalMillis count
     */
    @Test
    public void testExecutionTimeTotalMillis() {
        entityManagementInstrumentationBean.setCreateExecutionTimeTotalMillis(10l);
        entityManagementInstrumentationBean.setUpdateExecutionTimeTotalMillis(15l);
        entityManagementInstrumentationBean.setReadExecutionTimeTotalMillis(10l);
        entityManagementInstrumentationBean.setDeleteExecutionTimeTotalMillis(10l);

        entityManagementInstrumentationBean.setCreateExecutionTimeTotalMillis(5l);
        entityManagementInstrumentationBean.setUpdateExecutionTimeTotalMillis(5l);
        entityManagementInstrumentationBean.setReadExecutionTimeTotalMillis(10l);

        entityManagementInstrumentationBean.setDeleteExecutionTimeTotalMillis(10l);
        assertEquals(entityManagementInstrumentationBean.getCreateExecutionTimeTotalMillis(), 15l);
        assertEquals(entityManagementInstrumentationBean.getUpdateExecutionTimeTotalMillis(), 20l);
        assertEquals(entityManagementInstrumentationBean.getReadExecutionTimeTotalMillis(), 20l);
        assertEquals(entityManagementInstrumentationBean.getDeleteExecutionTimeTotalMillis(), 20l);
    }
}