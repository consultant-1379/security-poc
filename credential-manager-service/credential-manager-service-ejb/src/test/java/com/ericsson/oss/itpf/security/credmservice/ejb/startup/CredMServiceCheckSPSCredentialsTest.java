/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.security.credmservice.api.CredMServiceWeb;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringStatus;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCheckException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;

@RunWith(MockitoJUnitRunner.class)
public class CredMServiceCheckSPSCredentialsTest {

    @InjectMocks
    @Spy
    CredMServiceCheckSPSCredentials credMServiceCheckSPSCredentials;

    @Spy
    CredMServiceLastMonitoringStatus credMServiceLastMonitoringStatus;

    @Mock
    CredMServiceWeb credMServiceWeb;

    @Mock
    CredMServiceBeanProxy proxy;

    @Mock
    SystemRecorderWrapper systemRecorder;

    @Test
    public void timeoutPhysicalTest() {
        System.setProperty("configuration.env.cloud.deployment", "FALSE");
        Mockito.when(credMServiceCheckSPSCredentials.checkAndReturnCredentialManagerTimeoutFlag()).thenReturn(false);
        Mockito.doNothing().when(credMServiceCheckSPSCredentials).scheduleTimerForCheckSPSCredentials();
        credMServiceCheckSPSCredentials.timeoutHandler(null);
        Mockito.verify(systemRecorder, Mockito.times(1)).recordEvent(Mockito.anyString(), Mockito.any(EventLevel.class), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void timeoutcENMTest() {
        System.setProperty("configuration.env.cloud.deployment", "TRUE");
        final CredentialManagerMonitoringResponse monitoringResp = new CredentialManagerMonitoringResponse(200,
                CredentialManagerMonitoringStatus.ENABLED);
        Mockito.when(credMServiceWeb.getMonitoringStatus()).thenReturn(monitoringResp);
        Mockito.when(credMServiceLastMonitoringStatus.getLastMonitoringStatus()).thenReturn(CredentialManagerMonitoringStatus.ENABLED);
        Mockito.doNothing().when(credMServiceCheckSPSCredentials).scheduleTimerForCheckSPSCredentials();
        credMServiceCheckSPSCredentials.timeoutHandler(null);
        try {
            Mockito.verify(proxy, Mockito.times(1)).checkJBossCredentials();
        } catch (final CredentialManagerCheckException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void timeoutcENMInternalErrorTest() {
        System.setProperty("configuration.env.cloud.deployment", "TRUE");
        final CredentialManagerMonitoringResponse monitoringResp = new CredentialManagerMonitoringResponse(500,
                CredentialManagerMonitoringStatus.EMPTY);
        Mockito.when(credMServiceWeb.getMonitoringStatus()).thenReturn(monitoringResp);
        Mockito.when(credMServiceLastMonitoringStatus.getLastMonitoringStatus()).thenReturn(CredentialManagerMonitoringStatus.EMPTY);
        Mockito.doNothing().when(credMServiceCheckSPSCredentials).scheduleTimerForCheckSPSCredentials();
        credMServiceCheckSPSCredentials.timeoutHandler(null);
        Mockito.verify(systemRecorder, Mockito.times(1)).recordEvent(Mockito.anyString(), Mockito.any(EventLevel.class), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString());
    }
}
