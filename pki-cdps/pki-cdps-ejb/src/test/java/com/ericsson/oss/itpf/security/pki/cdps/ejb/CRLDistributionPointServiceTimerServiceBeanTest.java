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
package com.ericsson.oss.itpf.security.pki.cdps.ejb;

import javax.ejb.Timer;
import javax.ejb.TimerService;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationRequestMessage;
import com.ericsson.oss.itpf.security.pki.cdps.service.cluster.PKIRAMembershipListener;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;

/**
 * Test Class for CRLDistributionPointServiceTimerServiceBean.
 * 
 * @author xkumkam
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(TimerUtility.class)
public class CRLDistributionPointServiceTimerServiceBeanTest {

    @InjectMocks
    CRLDistributionPointServiceTimerServiceBean crlDistributionPointServiceTimerServiceBean;

    @Mock
    private TimerService timerService;

    @Mock
    private EventSender<CRLNotificationRequestMessage> crlNotificationRequestMessage;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private PKIRAMembershipListener pkiraMembershipListener;

    @Mock
    Logger logger;

    @Mock
    Timer timer;

    public static final String DEFAULT_SCHEDULER_TIME_FOR_PKI_CDPS = "*,*,*,*,3,0,0";
    public static final String PKI_CDPS_SCHEDULER_TIMER_INFO = "pkiCDPSSchedulerTimerInfo";

    @Test
    public void testTimeout() {
        Mockito.when(pkiraMembershipListener.isMaster()).thenReturn(true);
        crlDistributionPointServiceTimerServiceBean.timeout(timer);

        Mockito.verify(logger).info("End of timeout method in CRLDistributionPointServiceTimerServiceBean class");
    }

    @Test
    public void testTimeout_TimerException() {
        Mockito.when(pkiraMembershipListener.isMaster()).thenThrow(new TimerException("Timer Exception"));
        crlDistributionPointServiceTimerServiceBean.timeout(timer);

        Mockito.verify(logger).error("Could not schedule  CRLDistributionPointServiceTimerService job {}", "Timer Exception");
    }

    @Test
    public void testTimeout_Exception() {
        Mockito.when(pkiraMembershipListener.isMaster()).thenReturn(true);
        Mockito.doThrow(new TimerException("Exception Occured")).when(crlNotificationRequestMessage).send((CRLNotificationRequestMessage) Mockito.any());
        crlDistributionPointServiceTimerServiceBean.timeout(timer);

        Mockito.verify(logger).error("Sending notification message to get all CRL's for publishing and unpublishing to CDPS in CRLDistributionPointServiceTimerService due to {}", "Exception Occured");
    }

    @Test
    public void testScheduleJob() {
        crlDistributionPointServiceTimerServiceBean.scheduleJob();

        Mockito.verify(logger).info("End of scheduleJob method in CRLDistributionPointServiceTimerServiceBean class");
    }

    @Test
    public void testScheduleJob_TimerException() {
        PowerMockito.mockStatic(TimerUtility.class);
        PowerMockito.doThrow(new TimerException("Timer Exception")).when(TimerUtility.class);
        TimerUtility.createTimer(timerService, DEFAULT_SCHEDULER_TIME_FOR_PKI_CDPS, PKI_CDPS_SCHEDULER_TIMER_INFO);
        crlDistributionPointServiceTimerServiceBean.scheduleJob();

        Mockito.verify(logger).error("Could not schedule CRLDistributionPointServiceTimerService job {}", "Timer Exception");
    }

    @Test
    public void testCancelJob() {
        crlDistributionPointServiceTimerServiceBean.cancelJob();

        Mockito.verify(logger).info(PKI_CDPS_SCHEDULER_TIMER_INFO, " canceled");
    }

    @Test
    public void testCancelJob_TimerException() {
        PowerMockito.mockStatic(TimerUtility.class);
        PowerMockito.doThrow(new TimerException("Timer Exception")).when(TimerUtility.class);
        TimerUtility.cancelTimerByTimerConfig(timerService, PKI_CDPS_SCHEDULER_TIMER_INFO);
        crlDistributionPointServiceTimerServiceBean.cancelJob();

        Mockito.verify(logger).error(ErrorMessages.FAILED_TO_RECREATE_TIMER, "Timer Exception");
    }
}
