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
public class CAEntityCertificateManagementInstrumentationBeanTest {

    @InjectMocks
    CAEntityCertificateManagementInstrumentationBean caCertificateManagementInstrumentationBean;

    /**
     * Method to test Method Invocations count
     */
    @Test
    public void testMethodInvocations_CAEntity() {
        caCertificateManagementInstrumentationBean.setGenerateMethodInvocations();
        caCertificateManagementInstrumentationBean.setRenewMethodInvocations();
        caCertificateManagementInstrumentationBean.setRekeyMethodInvocations();

        caCertificateManagementInstrumentationBean.setGenerateMethodInvocations();
        caCertificateManagementInstrumentationBean.setRenewMethodInvocations();
        caCertificateManagementInstrumentationBean.setRekeyMethodInvocations();

        assertEquals(caCertificateManagementInstrumentationBean.getGenerateMethodInvocations(), 2);
        assertEquals(caCertificateManagementInstrumentationBean.getRenewMethodInvocations(), 2);
        assertEquals(caCertificateManagementInstrumentationBean.getRekeyMethodInvocations(), 2);
    }

    /**
     * Method to test Method Failures count
     */
    @Test
    public void testMethodFailure_CAEntity() {
        caCertificateManagementInstrumentationBean.setGenerateMethodFailures();
        caCertificateManagementInstrumentationBean.setRenewMethodFailures();
        caCertificateManagementInstrumentationBean.setRekeyMethodFailures();

        caCertificateManagementInstrumentationBean.setGenerateMethodFailures();
        caCertificateManagementInstrumentationBean.setRenewMethodFailures();
        caCertificateManagementInstrumentationBean.setRekeyMethodFailures();

        assertEquals(caCertificateManagementInstrumentationBean.getGenerateMethodFailures(), 2);
        assertEquals(caCertificateManagementInstrumentationBean.getRenewMethodFailures(), 2);
        assertEquals(caCertificateManagementInstrumentationBean.getRekeyMethodFailures(), 2);
    }

    /**
     * Method to test Method ExecutionTimeTotalMillis count
     */
    @Test
    public void testExecutionTimeTotalMillis_CAEntity() {
        caCertificateManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(10l);
        caCertificateManagementInstrumentationBean.setRenewExecutionTimeTotalMillis(15l);
        caCertificateManagementInstrumentationBean.setRekeyExecutionTimeTotalMillis(10l);

        caCertificateManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(5l);
        caCertificateManagementInstrumentationBean.setRenewExecutionTimeTotalMillis(5l);
        caCertificateManagementInstrumentationBean.setRekeyExecutionTimeTotalMillis(10l);

        assertEquals(caCertificateManagementInstrumentationBean.getGenerateExecutionTimeTotalMillis(), 15l);
        assertEquals(caCertificateManagementInstrumentationBean.getRenewExecutionTimeTotalMillis(), 20l);
        assertEquals(caCertificateManagementInstrumentationBean.getRekeyExecutionTimeTotalMillis(), 20l);
    }
}