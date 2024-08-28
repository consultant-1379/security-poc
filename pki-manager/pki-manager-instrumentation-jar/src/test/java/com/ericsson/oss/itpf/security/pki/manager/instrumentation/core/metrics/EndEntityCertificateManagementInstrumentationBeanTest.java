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
public class EndEntityCertificateManagementInstrumentationBeanTest {

    @InjectMocks
    EndEntityCertificateManagementInstrumentationBean certificateManagementInstrumentationBean;

    /**
     * Method to test Method Invocations count
     */
    @Test
    public void testMethodInvocations_EndEntity() {
        certificateManagementInstrumentationBean.setGenerateMethodInvocations();
        certificateManagementInstrumentationBean.setRenewMethodInvocations();
        certificateManagementInstrumentationBean.setRekeyMethodInvocations();

        certificateManagementInstrumentationBean.setGenerateMethodInvocations();
        certificateManagementInstrumentationBean.setRenewMethodInvocations();
        certificateManagementInstrumentationBean.setRekeyMethodInvocations();

        assertEquals(certificateManagementInstrumentationBean.getGenerateMethodInvocations(), 2);
        assertEquals(certificateManagementInstrumentationBean.getRenewMethodInvocations(), 2);
        assertEquals(certificateManagementInstrumentationBean.getRekeyMethodInvocations(), 2);
    }

    /**
     * Method to test Method Failures count
     */
    @Test
    public void testMethodFailure_EndEntity() {
        certificateManagementInstrumentationBean.setGenerateMethodFailures();
        certificateManagementInstrumentationBean.setRenewMethodFailures();
        certificateManagementInstrumentationBean.setRekeyMethodFailures();

        certificateManagementInstrumentationBean.setGenerateMethodFailures();
        certificateManagementInstrumentationBean.setRenewMethodFailures();
        certificateManagementInstrumentationBean.setRekeyMethodFailures();

        assertEquals(certificateManagementInstrumentationBean.getGenerateMethodFailures(), 2);
        assertEquals(certificateManagementInstrumentationBean.getRenewMethodFailures(), 2);
        assertEquals(certificateManagementInstrumentationBean.getRekeyMethodFailures(), 2);
    }

    /**
     * Method to test Method ExecutionTimeTotalMillis count
     */
    @Test
    public void testExecutionTimeTotalMillis_EndEntity() {
        certificateManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(10l);
        certificateManagementInstrumentationBean.setRenewExecutionTimeTotalMillis(15l);
        certificateManagementInstrumentationBean.setRekeyExecutionTimeTotalMillis(10l);

        certificateManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(5l);
        certificateManagementInstrumentationBean.setRenewExecutionTimeTotalMillis(5l);
        certificateManagementInstrumentationBean.setRekeyExecutionTimeTotalMillis(10l);

        assertEquals(certificateManagementInstrumentationBean.getGenerateExecutionTimeTotalMillis(), 15l);
        assertEquals(certificateManagementInstrumentationBean.getRenewExecutionTimeTotalMillis(), 20l);
        assertEquals(certificateManagementInstrumentationBean.getRekeyExecutionTimeTotalMillis(), 20l);
    }
}