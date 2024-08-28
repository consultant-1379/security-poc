/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.config.change.event.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.service.schedular.*;

@RunWith(MockitoJUnitRunner.class)
public class PkiManagerConfigChangeEventListenerTest {

    @InjectMocks
    private PkiManagerConfigChangeEventListener pkiManagerConfigChangeEventListener;

    @Mock
    private Logger logger;

    @Mock
    private PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Mock
    private PKIManagerStatusUpdateTimerServiceBean pkiManagerStatusUpdateTimerServiceBean;

    @Mock
    private GetLatestCRLTimerServiceBean getLatestCRLTimerServiceBean;

    @Mock
    private PkiCredentialsManagementTimerServiceBean pkiCredentialsManagementTimerServiceBean;

    @Mock
    private CACertExpiryNotificationTimerServiceBean caCertExpiryNotificationTimerServiceBean;

    @Mock
    private EntityCertExpiryNotificationTimerServiceBean entityCertExpiryNotificationTimerServiceBean;

    @Mock
    private ExternalCACRLTimerServiceBean externalCACRLTimerServiceBean;

    @Mock
    private SystemRecorder systemRecorder;

    private final String schedulerTimer = "*,*,*,*,2,0,0";
    private final String invalidSchedulerTime = "*,*,*,*,190,190,0";
    private final String schedulerTime = "*,*,*,*,1,1,0";

    @Test
    public void testListenForStatusUpdateTimeChange() {

        pkiManagerConfigChangeEventListener.listenForStatusUpdateTimeChange(schedulerTime);

        Mockito.verify(pkiManagerConfigurationListener).getStatusUpdateSchedulerTime();
    }

    @Test
    public void testListenForStatusUpdateTimeChange_InvalidScheduleTime_ThrowsTimerException() {

        Mockito.doThrow(new TimerException()).when(pkiManagerStatusUpdateTimerServiceBean).resetIntervalTimer(invalidSchedulerTime);

        pkiManagerConfigChangeEventListener.listenForStatusUpdateTimeChange(invalidSchedulerTime);

        Mockito.verify(logger).error(Mockito.anyString(), Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void testListenForFetchLatestCRLsSchedulerTimeChange() {

        pkiManagerConfigChangeEventListener.listenForFetchLatestCRLsSchedulerTimeChange(schedulerTime);

        Mockito.verify(pkiManagerConfigurationListener).getFetchLatestCRLsSchedulerTime();
    }

    @Test
    public void testListenForFetchLatestCRLsSchedulerTimeChange_InvalidScheduleTime_ThrowsTimerException() {

        Mockito.doThrow(new TimerException()).when(getLatestCRLTimerServiceBean).resetIntervalTimer(invalidSchedulerTime);

        pkiManagerConfigChangeEventListener.listenForFetchLatestCRLsSchedulerTimeChange(invalidSchedulerTime);

        Mockito.verify(logger).error(Mockito.anyString(), Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void testListenForPkiManagerCredentialsManagementSchedulerTimeChange() {

        pkiManagerConfigChangeEventListener.listenForPkiManagerCredentialsManagementSchedulerTimeChange(schedulerTime);

        Mockito.verify(pkiCredentialsManagementTimerServiceBean).scheduleJob();
    }

    @Test
    public void testListenForCaCertExpiryNotifySchedulerTimeChange() {

        pkiManagerConfigChangeEventListener.listenForCaCertExpiryNotifySchedulerTimeChange(schedulerTimer);

        Mockito.verify(caCertExpiryNotificationTimerServiceBean).setTimer();
    }

    @Test
    public void testListenForEntityCertExpiryNotifySchedulerTimeChange() {

        pkiManagerConfigChangeEventListener.listenForEntityCertExpiryNotifySchedulerTimeChange(schedulerTimer);

        Mockito.verify(entityCertExpiryNotificationTimerServiceBean).setTimer();
    }

    @Test
    public void testListenForExternalCACRLSchedulerTimeChange() {

        pkiManagerConfigChangeEventListener.listenForExternalCACRLSchedulerTimeChange(schedulerTime);

        Mockito.verify(externalCACRLTimerServiceBean).scheduleJob();
    }

}