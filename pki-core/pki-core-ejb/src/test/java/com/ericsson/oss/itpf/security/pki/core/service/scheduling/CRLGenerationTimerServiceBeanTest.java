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
package com.ericsson.oss.itpf.security.pki.core.service.scheduling;

import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.core.service.config.PKICoreConfigurationParams;

@RunWith(MockitoJUnitRunner.class)
public class CRLGenerationTimerServiceBeanTest {

    @Mock
    MembershipListenerInterface membershipListener;

    @InjectMocks
    CRLGenerationTimerServiceBean crlGenerationTimerServiceBean;

    @Mock
    private Timer timer;

    @Mock
    private Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    private PKICoreConfigurationParams configurationListener;

    @Mock
    private TimerService timerService;

    @Mock
    private CRLGenerationBean crlGenerationBean;

    @Mock
    private CAEntityPersistenceHandler caEntityPersistenceHandler;

    private List<CertificateAuthority> certificateAuthorityList = null;

    @Before
    public void setup() {
        certificateAuthorityList = new ArrayList<CertificateAuthority>();
    }

    @Test
    public void testTimeoutIsMaster() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        doNothing().when(crlGenerationBean).generateCRL(Mockito.anyString(), Mockito.any(Certificate.class));
        when(caEntityPersistenceHandler.getAllCAsByStatus(CAStatus.ACTIVE, CAStatus.INACTIVE)).thenReturn(certificateAuthorityList);

        crlGenerationTimerServiceBean.timeout(timer);

        verify(logger).debug("End of timeout method in CRLGenerationTimerServiceBean class");
    }

    @Test
    public void testTimeoutIsSlave() {
        Mockito.when(membershipListener.isMaster()).thenReturn(false);
        crlGenerationTimerServiceBean.timeout(timer);

        verify(logger).debug("End of timeout method in CRLGenerationTimerServiceBean class");
    }

    @Test
    public void testTimeoutThrowsCRLServiceException() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        doThrow(CRLServiceException.class).when(crlGenerationBean).generateCRL(Mockito.anyString(), Mockito.any(Certificate.class));
        crlGenerationTimerServiceBean.timeout(timer);

        verify(logger).debug("End of timeout method in CRLGenerationTimerServiceBean class");
    }

    @Test
    public void testTimeoutThrowsException() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        doThrow(Exception.class).when(crlGenerationBean).generateCRL(Mockito.anyString(), Mockito.any(Certificate.class));

        crlGenerationTimerServiceBean.timeout(timer);

        verify(logger).debug("End of timeout method in CRLGenerationTimerServiceBean class");
    }

    @Test
    public void testScheduleJob() {
        final String generateCRLSchedulerTime = "*,*,*,*,1,1,0";
        final ScheduleExpression schedule = StringUtility.getScheduleExpressionFromString(generateCRLSchedulerTime);
        final TimerConfig timerConfig = new TimerConfig("crlGenerationSchedular", true);
        when(timerService.createCalendarTimer(schedule, timerConfig)).thenReturn(timer);

        crlGenerationTimerServiceBean.scheduleJob();

        verify(logger).debug("End of ScheduleJob method invoked in CRLGenerationTimerServiceBean class");
    }

    @Test
    public void testScheduleJobHavingSchedulerTimeAsNull() {
        crlGenerationTimerServiceBean.scheduleJob();

        verify(logger).error(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name generateCRLSchedulerTime. Could not schedule PKICore CRL Generation Timer job");
    }
}
