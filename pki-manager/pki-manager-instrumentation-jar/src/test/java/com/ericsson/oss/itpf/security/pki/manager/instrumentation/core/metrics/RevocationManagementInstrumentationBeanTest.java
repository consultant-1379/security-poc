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
public class RevocationManagementInstrumentationBeanTest {

    @InjectMocks
    RevocationManagementInstrumentationBean revocationManagementInstrumentationBean;

    /**
     * Method to test Method Invocations count
     */
    @Test
    public void testRevokeMethodInvocations() {
        revocationManagementInstrumentationBean.setRevokeMethodInvocations();
        revocationManagementInstrumentationBean.setRevokeMethodInvocations();

        assertEquals(revocationManagementInstrumentationBean.getRevokeMethodInvocations(), 2);
    }

    /**
     * Method to test Method Failures count
     */
    @Test
    public void testRevokeMethodFailure() {
        revocationManagementInstrumentationBean.setRevokeMethodFailures();
        revocationManagementInstrumentationBean.setRevokeMethodFailures();

        assertEquals(revocationManagementInstrumentationBean.getRevokeMethodFailures(), 2);
    }

    /**
     * Method to test Method ExecutionTimeTotalMillis count
     */
    @Test
    public void testRevokeExecutionTimeTotalMillis() {
        revocationManagementInstrumentationBean.setRevokeExecutionTimeTotalMillis(10l);
        revocationManagementInstrumentationBean.setRevokeExecutionTimeTotalMillis(5l);

        assertEquals(revocationManagementInstrumentationBean.getRevokeExecutionTimeTotalMillis(), 15l);
    }
}