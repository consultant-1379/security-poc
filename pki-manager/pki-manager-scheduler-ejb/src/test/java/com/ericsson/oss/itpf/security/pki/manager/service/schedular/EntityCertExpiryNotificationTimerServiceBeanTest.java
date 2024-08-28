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
package com.ericsson.oss.itpf.security.pki.manager.service.schedular;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.ejb.ScheduleExpression;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.CertificateExpiryNotificationHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertExpiryNotificationTimerServiceBeanTest {

    @InjectMocks
    EntityCertExpiryNotificationTimerServiceBean entityCertExpiryNotificationTimerServiceBean;

    @Mock
    CertificateExpiryNotificationHandler certificateExpiryNotificationDetails;

    @Mock
    Logger logger;

    @Mock
    private TimerService timerService;

    @Mock
    private PKIManagerConfigurationListener configurationListener;

    @Mock
    MembershipListenerInterface membershipListener;

    @Mock
    private Timer timer;

    @Mock
    private TimerConfig timerConfig;

    @Mock
    private ScheduleExpression schedule;

    @Mock
    private SystemRecorder systemRecorder;

    /**
     * tests setTimer method in positive scenario.
     */

    @Test
    public void testSetTimer() {
        when(timerService.createCalendarTimer(schedule, timerConfig)).thenReturn(timer);
        when(configurationListener.getCaCertExpiryNotifySchedulerTime()).thenReturn("*,*,*,*,2,0,0");
        entityCertExpiryNotificationTimerServiceBean.setTimer();
        verify(logger).debug("Setting the timer for entity CertExpiryNotificationScheduler job.");
    }

    @Test
    public void testSetTimer2() {
        when(timerService.createCalendarTimer(schedule, timerConfig)).thenReturn(timer);
        when(configurationListener.getCaCertExpiryNotifySchedulerTime()).thenReturn(null);
        entityCertExpiryNotificationTimerServiceBean.setTimer();
        verify(logger).error("{} with name entityCertExpiryNotifySchedulerTime. Could not schedule PKIManager EntityCertExpiryNotification job.", ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL);
    }

    /**
     * tests timeOut method by passing CA cart expire schedule time.
     */
    @Test
    public void testTimeOut() {
        Mockito.doNothing().when(certificateExpiryNotificationDetails).handle(EntityType.CA_ENTITY);
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        entityCertExpiryNotificationTimerServiceBean.timeout(timer);
    }

    @Test
    public void testTimeoutThrowsCRLServiceException() {
        doThrow(Exception.class).when(certificateExpiryNotificationDetails).handle(EntityType.CA_ENTITY);
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        entityCertExpiryNotificationTimerServiceBean.timeout(timer);
    }

    @Test
    public void testSetTimerException() {
        when(timerService.createCalendarTimer(schedule, timerConfig)).thenReturn(timer);
        when(configurationListener.getCaCertExpiryNotifySchedulerTime()).thenThrow(TimerException.class);
        entityCertExpiryNotificationTimerServiceBean.setTimer();

    }
}
