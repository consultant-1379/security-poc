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

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics.EndEntityCertificateManagementInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

@RunWith(MockitoJUnitRunner.class)
public class EndEntityCertificateManagementInstrumentationServiceTest {

    @InjectMocks
    EntityCertificateManagementInstrumentationService entityCertificateManagementInstrumentationService;

    @Mock
    EndEntityCertificateManagementInstrumentationBean entityCertificateManagementInstrumentationBean;

    long timeInMillis = System.currentTimeMillis();

    @Test
    public void testGenerateMethodInvocations() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setGenerateMethodInvocations();
        entityCertificateManagementInstrumentationService.setMethodInvocations(MetricType.GENERATE);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setGenerateMethodInvocations();
    }

    @Test
    public void testRenewMethodInvocations() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setRenewMethodInvocations();
        entityCertificateManagementInstrumentationService.setMethodInvocations(MetricType.RENEW);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setRenewMethodInvocations();
    }

    @Test
    public void testRekeyMethodInvocations() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setRekeyMethodInvocations();
        entityCertificateManagementInstrumentationService.setMethodInvocations(MetricType.REKEY);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setRekeyMethodInvocations();
    }

    @Test
    public void testGenerateMethodFailures() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setGenerateMethodFailures();
        entityCertificateManagementInstrumentationService.setMethodFailures(MetricType.GENERATE);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setGenerateMethodFailures();
    }

    @Test
    public void testRenewMethodFailures() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setRenewMethodFailures();
        entityCertificateManagementInstrumentationService.setMethodFailures(MetricType.RENEW);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setRenewMethodFailures();
    }

    @Test
    public void testRekeyMethodFailures() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setRekeyMethodFailures();
        entityCertificateManagementInstrumentationService.setMethodFailures(MetricType.REKEY);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setRekeyMethodFailures();
    }

    @Test
    public void testGenerateMethodTimeInMillis() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setGenerateExecutionTimeTotalMillis(timeInMillis);
        entityCertificateManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.GENERATE, timeInMillis);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setGenerateExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testRenewMethodTimeInMillis() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setRenewExecutionTimeTotalMillis(timeInMillis);
        entityCertificateManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.RENEW, timeInMillis);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setRenewExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testRekeyMethodTimeInMillis() {
        Mockito.doNothing().when(entityCertificateManagementInstrumentationBean).setRekeyExecutionTimeTotalMillis(timeInMillis);
        entityCertificateManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.REKEY, timeInMillis);
        Mockito.verify(entityCertificateManagementInstrumentationBean).setRekeyExecutionTimeTotalMillis(timeInMillis);
    }
}