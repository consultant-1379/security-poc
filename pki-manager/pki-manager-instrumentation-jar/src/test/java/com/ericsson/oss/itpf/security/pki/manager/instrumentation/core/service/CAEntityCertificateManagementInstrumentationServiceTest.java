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
import org.mockito.InjectMocks;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics.CAEntityCertificateManagementInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityCertificateManagementInstrumentationServiceTest {

    @Mock
    CAEntityCertificateManagementInstrumentationBean caEntityCertificateManagementInstrumentationBeanMock;

    @InjectMocks
    CAEntityCertificateManagementInstrumentationService caEntityCertificateManagementInstrumentationService;

    long timeInMillis = System.currentTimeMillis();

    @Test
    public void testGenerateMethodInvocations() {

        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setGenerateMethodInvocations();
        caEntityCertificateManagementInstrumentationService.setMethodInvocations(MetricType.GENERATE);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setGenerateMethodInvocations();
    }

    @Test
    public void testRenewMethodInvocations() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setRenewMethodInvocations();
        caEntityCertificateManagementInstrumentationService.setMethodInvocations(MetricType.RENEW);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setRenewMethodInvocations();
    }

    @Test
    public void testRekeyMethodInvocations() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setRekeyMethodInvocations();
        caEntityCertificateManagementInstrumentationService.setMethodInvocations(MetricType.REKEY);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setRekeyMethodInvocations();
    }

    @Test
    public void testGenerateMethodFailures() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setGenerateMethodFailures();
        caEntityCertificateManagementInstrumentationService.setMethodFailures(MetricType.GENERATE);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setGenerateMethodFailures();
    }

    @Test
    public void testRenewMethodFailures() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setRenewMethodFailures();
        caEntityCertificateManagementInstrumentationService.setMethodFailures(MetricType.RENEW);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setRenewMethodFailures();
    }

    @Test
    public void testRekeyMethodFailures() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setRekeyMethodFailures();
        caEntityCertificateManagementInstrumentationService.setMethodFailures(MetricType.REKEY);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setRekeyMethodFailures();
    }

    @Test
    public void testGenerateMethodTimeInMillis() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setGenerateExecutionTimeTotalMillis(timeInMillis);
        caEntityCertificateManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.GENERATE, timeInMillis);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setGenerateExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testRenewMethodTimeInMillis() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setRenewExecutionTimeTotalMillis(timeInMillis);
        caEntityCertificateManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.RENEW, timeInMillis);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setRenewExecutionTimeTotalMillis(timeInMillis);
    }

    @Test
    public void testRekeyMethodTimeInMillis() {
        Mockito.doNothing().when(caEntityCertificateManagementInstrumentationBeanMock).setRekeyExecutionTimeTotalMillis(timeInMillis);
        caEntityCertificateManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.REKEY, timeInMillis);
        Mockito.verify(caEntityCertificateManagementInstrumentationBeanMock).setRekeyExecutionTimeTotalMillis(timeInMillis);
    }

}