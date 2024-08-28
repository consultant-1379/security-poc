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

package com.ericsson.oss.itpf.security.pki.ra.cmp.service.scheduler;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.ejb.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPCrlCacheLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource.listener.ReflectionTestUtils;

@RunWith(PowerMockRunner.class)
public class CmpCrlCacheLoaderTimerServiceBeanTest {

    @InjectMocks
    private CmpCrlCacheLoaderTimerServiceBean cmpCrlCacheLoaderTimerServiceBean;

    @Mock
    CMPCrlCacheLocalService crlCacheLocalService;

    @Mock
    ServiceFinderBean serviceFinderBean;

    @Mock
    private Timer timer;

    @Mock
    private Logger logger;

    @Mock
    private ConfigurationParamsListener configurationParamsListener;

    @Mock
    private TimerService timerService;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private MembershipListenerInterface membershipListener;

    @Before
    public void startup() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
    }

    @Mock
    TimerUtility timerUtility;

    @Test
    public void testTimeout() throws SecurityException, IllegalAccessException {

        MockitoAnnotations.initMocks(this);
        ReflectionTestUtils.setPrimitiveField(CmpCrlCacheLoaderTimerServiceBean.class, ServiceFinderBean.class, "serviceFinder",
                cmpCrlCacheLoaderTimerServiceBean, serviceFinderBean);
        when(serviceFinderBean.find(CMPCrlCacheLocalService.class)).thenReturn(crlCacheLocalService);
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        cmpCrlCacheLoaderTimerServiceBean.timeout(timer);
        Mockito.verify(logger).info("End of timeout method in CMPCRLCacheLoaderTimerServiceBean class");
    }

    @Test
    public void testTimeout_InvalidTimer_ThrowsTimerException() {

        PowerMockito.mockStatic(TimerUtility.class);

        PowerMockito.doThrow(new Exception()).when(TimerUtility.class);

        cmpCrlCacheLoaderTimerServiceBean.timeout(timer);
    }

    @Test
    public void testScheduleJob() {

        PowerMockito.mockStatic(TimerUtility.class);

        cmpCrlCacheLoaderTimerServiceBean.scheduleJob();

        PowerMockito.verifyStatic(Mockito.times(1));
    }

    @Test
    public void testScheduleJob_IllegalArgument_ThrowsTimerException() {

        Mockito.doThrow(new IllegalArgumentException()).when(timerService)
                .createCalendarTimer((ScheduleExpression) Matchers.anyObject(), (TimerConfig) Matchers.anyObject());

        cmpCrlCacheLoaderTimerServiceBean.scheduleJob();

        verify(logger).error(anyString(), anyString());
    }
}
