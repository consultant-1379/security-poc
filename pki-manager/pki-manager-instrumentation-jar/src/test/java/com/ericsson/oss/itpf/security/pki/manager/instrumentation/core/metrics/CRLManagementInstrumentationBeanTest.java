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
public class CRLManagementInstrumentationBeanTest {

    @InjectMocks
    CRLManagementInstrumentationBean crlManagementInstrumentationBean;

    /**
     * Method to test Method Invocations count
     */
    @Test
    public void testGenerateMethodInvocations() {
        crlManagementInstrumentationBean.setGenerateMethodInvocations();
        crlManagementInstrumentationBean.setGenerateMethodInvocations();

        assertEquals(crlManagementInstrumentationBean.getGenerateMethodInvocations(), 2);
    }

    /**
     * Method to test Method Failures count
     */
    @Test
    public void testGenerateMethodFailure() {
        crlManagementInstrumentationBean.setGenerateMethodFailures();
        crlManagementInstrumentationBean.setGenerateMethodFailures();

        assertEquals(crlManagementInstrumentationBean.getGenerateMethodFailures(), 2);
    }

    /**
     * Method to test Method ExecutionTimeTotalMillis count
     */
    @Test
    public void testGenerateExecutionTimeTotalMillis() {
        crlManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(10l);
        crlManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(5l);

        assertEquals(crlManagementInstrumentationBean.getGenerateExecutionTimeTotalMillis(), 15l);
    }
}