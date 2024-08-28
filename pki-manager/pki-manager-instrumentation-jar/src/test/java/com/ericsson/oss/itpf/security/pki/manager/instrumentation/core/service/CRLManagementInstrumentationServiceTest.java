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

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics.CRLManagementInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

@RunWith(MockitoJUnitRunner.class)
public class CRLManagementInstrumentationServiceTest {

    @InjectMocks
    CRLManagementInstrumentationService crlManagementInstrumentationService;

    @Mock
    CRLManagementInstrumentationBean crlManagementInstrumentationBean;

    long timeInMillis = System.currentTimeMillis();

    @Test
    public void testGenerateMethodInvocations() {
        Mockito.doNothing().when(crlManagementInstrumentationBean).setGenerateMethodInvocations();
        crlManagementInstrumentationService.setMethodInvocations(MetricType.GENERATE);
        Mockito.verify(crlManagementInstrumentationBean).setGenerateMethodInvocations();
    }

    @Test
    public void testGenerateMethodFailures() {
        Mockito.doNothing().when(crlManagementInstrumentationBean).setGenerateMethodFailures();
        crlManagementInstrumentationService.setMethodFailures(MetricType.GENERATE);
        Mockito.verify(crlManagementInstrumentationBean).setGenerateMethodFailures();
    }

    @Test
    public void testGenerateMethodTimeInMillis() {
        Mockito.doNothing().when(crlManagementInstrumentationBean).setGenerateExecutionTimeTotalMillis(timeInMillis);
        crlManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.GENERATE, timeInMillis);
        Mockito.verify(crlManagementInstrumentationBean).setGenerateExecutionTimeTotalMillis(timeInMillis);
    }

}