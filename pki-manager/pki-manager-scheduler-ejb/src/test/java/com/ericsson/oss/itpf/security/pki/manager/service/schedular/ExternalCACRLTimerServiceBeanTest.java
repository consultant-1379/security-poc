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

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.ejb.ScheduleExpression;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.ExternalCACRLHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

/**
 * Junit Tests for ExternalCACRLTimerServiceBean.
 * 
 * @author tcsviku
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ExternalCACRLTimerServiceBeanTest {

    @InjectMocks
    ExternalCACRLTimerServiceBean externalCACRLTimerServiceBean;

    @Mock
    private Timer timer;

    @Mock
    private Logger logger;

    @Mock
    private PKIManagerConfigurationListener configurationListener;

    @Mock
    private TimerService timerService;

    @Mock
    MembershipListenerInterface membershipListener;

    @Mock
    ExternalCACRLHandler externalCACRLHandler;

    @Mock
    private SystemRecorder systemRecorder;

    @Before
    public void startup() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
    }

    @Test
    public void testTimeout() {
        doNothing().when(externalCACRLHandler).externalCACRLHandle();

        externalCACRLTimerServiceBean.timeout(timer);

        verify(logger).debug("End of timeout method in ExternalCACRLTimerServiceBean class.");
    }

    @Test
    public void testTimeoutThrowsCRLServiceException() {
        doThrow(CRLServiceException.class).when(externalCACRLHandler).externalCACRLHandle();

        externalCACRLTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
        verify(logger).debug("End of timeout method in ExternalCACRLTimerServiceBean class.");
    }

    @Test
    public void testTimeoutThrowsException() {
        doThrow(Exception.class).when(externalCACRLHandler).externalCACRLHandle();

        externalCACRLTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
        verify(logger).debug("End of timeout method in ExternalCACRLTimerServiceBean class.");
    }

    @Test
    public void testScheduleJob() {
        final String externalCACRLsSchedulerTime = "*,*,*,*,3,1,0";
        when(configurationListener.getExternalCACRLsSchedulerTime()).thenReturn(externalCACRLsSchedulerTime);

        final ScheduleExpression schedule = StringUtility.getScheduleExpressionFromString(externalCACRLsSchedulerTime);
        final TimerConfig timerConfig = new TimerConfig("getExternalCACRLTimer", true);
        when(timerService.createCalendarTimer(schedule, timerConfig)).thenReturn(timer);

        externalCACRLTimerServiceBean.scheduleJob();

        verify(logger).debug("ScheduleJob method has been invoked in externalCACRLTimerServiceBean class.");
    }

    @Test
    public void testScheduleJobHavingSchedulerTimeAsNull() {

        externalCACRLTimerServiceBean.scheduleJob();

        verify(logger).error("{} with name externalCACRLsSchedulerTime. Could not schedule PKIManager ExternalCACRLs job.", ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL);
    }
}
