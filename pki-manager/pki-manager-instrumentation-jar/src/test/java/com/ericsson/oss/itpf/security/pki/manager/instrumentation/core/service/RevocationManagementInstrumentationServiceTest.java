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

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics.RevocationManagementInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

@RunWith(MockitoJUnitRunner.class)
public class RevocationManagementInstrumentationServiceTest {

    @Mock
    RevocationManagementInstrumentationBean revocationManagementInstrumentationBean;

    @InjectMocks
    RevocationManagementInstrumentationService revocationManagementInstrumentationService;

    long timeInMillis = System.currentTimeMillis();

    @Test
    public void testRevokeMethodInvocations() {
        Mockito.doNothing().when(revocationManagementInstrumentationBean).setRevokeMethodInvocations();
        revocationManagementInstrumentationService.setMethodInvocations(MetricType.REVOKE);
        Mockito.verify(revocationManagementInstrumentationBean).setRevokeMethodInvocations();
    }

    @Test
    public void testRevokeMethodFailures() {
        Mockito.doNothing().when(revocationManagementInstrumentationBean).setRevokeMethodFailures();
        revocationManagementInstrumentationService.setMethodFailures(MetricType.REVOKE);
        Mockito.verify(revocationManagementInstrumentationBean).setRevokeMethodFailures();
    }

    @Test
    public void testRevokeMethodTimeInMillis() {
        Mockito.doNothing().when(revocationManagementInstrumentationBean).setRevokeExecutionTimeTotalMillis(timeInMillis);
        revocationManagementInstrumentationService.setExecutionTimeTotalMillis(MetricType.REVOKE, timeInMillis);
        Mockito.verify(revocationManagementInstrumentationBean).setRevokeExecutionTimeTotalMillis(timeInMillis);
    }

}