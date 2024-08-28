/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.schedular;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import javax.ejb.ScheduleExpression;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;

@RunWith(PowerMockRunner.class)
public class PkiCredentialsManagementTimerServiceBeanTest {

    @InjectMocks
    private PkiCredentialsManagementTimerServiceBean pkiCredentialsManagementTimerServiceBean;

    @Mock
    private Timer timer;

    @Mock
    private CredentialsManager credentialsManager;

    @Mock
    private Logger logger;

    @Mock
    private PKIManagerConfigurationListener configurationListener;

    @Mock
    private TimerService timerService;

    @Mock
    SystemRecorder systemRecorder;

    final private String pkiManagerCredentialsManagementSchedulerTime = "*,*,*,*,1,1,0";

    @Test
    public void testTimeout() {

        Mockito.when(configurationListener.getPkiManagerCredentialsManagementSchedulerTime()).thenReturn(pkiManagerCredentialsManagementSchedulerTime);

        pkiCredentialsManagementTimerServiceBean.timeout(timer);

        verify(credentialsManager).generatePkiCredentials();
    }

    @Test
    public void testTimeout_InvalidTimer_ThrowsTimerException() {

        Mockito.when(configurationListener.getPkiManagerCredentialsManagementSchedulerTime()).thenReturn(pkiManagerCredentialsManagementSchedulerTime);

        Mockito.doThrow(new IllegalArgumentException()).when(timerService).createCalendarTimer((ScheduleExpression) Mockito.anyObject(), (TimerConfig) Mockito.anyObject());

        pkiCredentialsManagementTimerServiceBean.timeout(timer);

        verify(credentialsManager).generatePkiCredentials();

    }

    @Test
    public void testTimeout_EntityNotAvailable_ThrowsCredentialsManagementServiceException() {

        doThrow(CredentialsManagementServiceException.class).when(credentialsManager).generatePkiCredentials();

        pkiCredentialsManagementTimerServiceBean.timeout(timer);

        verify(credentialsManager).generatePkiCredentials();
    }

    @Test
    public void testScheduleJob() {

        PowerMockito.mockStatic(TimerUtility.class);

        pkiCredentialsManagementTimerServiceBean.scheduleJob();

        PowerMockito.verifyStatic(Mockito.times(1));
    }

    @Test
    public void testScheduleJob_IllegalArgument_ThrowsTimerException() {

        Mockito.doThrow(new IllegalArgumentException()).when(timerService).createCalendarTimer((ScheduleExpression) Mockito.anyObject(), (TimerConfig) Mockito.anyObject());

        pkiCredentialsManagementTimerServiceBean.scheduleJob();

        verify(logger).error(anyString(), anyString());
    }

    @Test
    public void testScheduleJob_NoConfigurationProperty_ThrowsConfigurationPropertyNotFoundException() {

        Mockito.doThrow(new ConfigurationPropertyNotFoundException(ErrorMessages.CONFIGURATION_PROPERTY_NOT_FOUND)).when(timerService)
                .createCalendarTimer((ScheduleExpression) Mockito.anyObject(), (TimerConfig) Mockito.anyObject());

        pkiCredentialsManagementTimerServiceBean.scheduleJob();

        verify(logger).error("{} with name pkiManagerCredentialsManagementSchedulerTime. Could not schedule PKIManager getPkiCredentialCerts job.", ErrorMessages.CONFIGURATION_PROPERTY_NOT_FOUND);
    }
}
