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

import static org.mockito.Mockito.*;

import javax.ejb.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

@RunWith(MockitoJUnitRunner.class)
public class GetLatestCRLTimerServiceBeanTest {

    @InjectMocks
    GetLatestCRLTimerServiceBean getLatestCRLTimerServiceBean;

    @Mock
    private Timer timer;

    @Mock
    private CRLManager crlManager;

    @Mock
    private Logger logger;

    @Mock
    private PKIManagerConfigurationListener configurationListener;

    @Mock
    private TimerService timerService;

    @Mock
    MembershipListenerInterface membershipListener;

    @Mock
    SystemRecorder systemRecorder;

    @Before
    public void startup() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
    }

    @Test
    public void testTimeout() {
        doNothing().when(crlManager).getLatestCRLs();

        getLatestCRLTimerServiceBean.timeout(timer);

        verify(logger).debug("End of timeout method in GetLatestCRLTimerServiceBean class");
    }

    @Test
    public void testTimeoutThrowsCRLServiceException() {
        doThrow(CRLServiceException.class).when(crlManager).getLatestCRLs();

        getLatestCRLTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
        verify(logger).debug("End of timeout method in GetLatestCRLTimerServiceBean class");
    }

    @Test
    public void testTimeoutThrowsException() {
        doThrow(Exception.class).when(crlManager).getLatestCRLs();

        getLatestCRLTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
        verify(logger).debug("End of timeout method in GetLatestCRLTimerServiceBean class");
    }

    @Test
    public void testScheduleJob() {
        final String fetchLatestCRLsSchedulerTime = "*,*,*,*,1,1,0";
        when(configurationListener.getFetchLatestCRLsSchedulerTime()).thenReturn(fetchLatestCRLsSchedulerTime);

        final ScheduleExpression schedule = StringUtility.getScheduleExpressionFromString(fetchLatestCRLsSchedulerTime);
        final TimerConfig timerConfig = new TimerConfig("getLatestCRLTimer", true);
        when(timerService.createCalendarTimer(schedule, timerConfig)).thenReturn(timer);

        getLatestCRLTimerServiceBean.scheduleJob();

        verify(logger).debug("End of ScheduleJob method invoked in GetLatestCRLTimerServiceBean class");
    }

    @Test
    public void testScheduleJobHavingSchedulerTimeAsNull() {

        getLatestCRLTimerServiceBean.scheduleJob();

        verify(logger).error(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name fetchLatestCRLsSchedulerTime. Could not schedule PKIManager GetLatestCRLTimerInfo Timer job");
    }
    
    @Test
    public void testScheduleJobException() {
        doThrow(Exception.class).when(configurationListener).getFetchLatestCRLsSchedulerTime();

        getLatestCRLTimerServiceBean.scheduleJob();

        verify(logger).debug("End of ScheduleJob method invoked in GetLatestCRLTimerServiceBean class");
    }
    
    @Test
    public void testScheduleJobConfigurationPropertyNotFoundException() {
        doThrow(ConfigurationPropertyNotFoundException.class).when(configurationListener).getFetchLatestCRLsSchedulerTime();

        getLatestCRLTimerServiceBean.scheduleJob();

        verify(logger).debug("End of ScheduleJob method invoked in GetLatestCRLTimerServiceBean class");
    }
   

    @Test
    public void testResetIntervalTimer() {
        final String fetchLatestCRLsSchedulerTime = "*,*,*,*,1,1,0";
        getLatestCRLTimerServiceBean.resetIntervalTimer(fetchLatestCRLsSchedulerTime);
        verify(logger).debug("End of resetIntervalTimer method invoked in GetLatestCRLTimerServiceBean class");
        
    }
}
