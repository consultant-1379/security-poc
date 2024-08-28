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

package com.ericsson.oss.itpf.security.pki.manager.service.schedular;

import static org.mockito.Matchers.anyString;

import javax.ejb.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.helper.AlgorithmLoader;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SupportedAlgorithmsCacheOperations;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

/**
 * Junit Tests for SupportedAlgorithmsCacheLoaderTimerServiceBean to load supported algorithms cache at a particular time interval defined by schedulerTime.
 * 
 * @author xchowja
 */
@RunWith(PowerMockRunner.class)
public class SupportedAlgorithmsCacheLoaderTimerServiceBeanTest {

    @InjectMocks
    SupportedAlgorithmsCacheLoaderTimerServiceBean supportedAlgorithmsCacheLoaderTimerServiceBean;

    @Mock
    Logger logger;

    @Mock
    TimerService timerService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    private Timer timer;

    @Mock
    MembershipListenerInterface membershipListenerInterface;

    @Mock
    SupportedAlgorithmsCacheOperations supportAlgorithmsCacheOperations;

    @Mock
    AlgorithmLoader algorithmLoader;

    @Test
    public void testTimeout() {

        Mockito.when(membershipListenerInterface.isMaster()).thenReturn(true);

        supportedAlgorithmsCacheLoaderTimerServiceBean.timeout(timer);

        Mockito.verify(supportAlgorithmsCacheOperations).load();
    }

    @Test
    public void testTimeout_Exception() {

        PowerMockito.mockStatic(TimerUtility.class);

        Mockito.when(membershipListenerInterface.isMaster()).thenReturn(true);

        PowerMockito.doThrow(new Exception()).when(TimerUtility.class);

        supportedAlgorithmsCacheLoaderTimerServiceBean.timeout(timer);

    }

    @Test
    public void testScheduleJob() {

        PowerMockito.mockStatic(TimerUtility.class);

        supportedAlgorithmsCacheLoaderTimerServiceBean.scheduleJob();

        PowerMockito.verifyStatic(Mockito.times(1));
    }

    @Test
    public void testScheduleJob_TimerException() {

        Mockito.doThrow(new TimerException()).when(timerService).createCalendarTimer((ScheduleExpression) Matchers.anyObject(), (TimerConfig) Matchers.anyObject());

        supportedAlgorithmsCacheLoaderTimerServiceBean.scheduleJob();

        Mockito.verify(logger).error(anyString(), anyString());
    }
}
