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

import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.*;

import javax.ejb.*;
import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.CertificateStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.TDPSUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

@RunWith(MockitoJUnitRunner.class)
public class PKIManagerStatusUpdateTimerServiceBeanTest {

    @InjectMocks
    private PKIManagerStatusUpdateTimerServiceBean pkiManagerStatusUpdateTimerServiceBean;

    @Mock
    private Timer timer;

    @Mock
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    private CertificateManagementService coreCertificateManagementService;

    @Mock
    private CRLManager crlManager;

    @Mock
    private CRLManagementService coreCRLManagementService;

    @Mock
    private Logger logger;

    @Mock
    private PKIManagerConfigurationListener configurationListener;

    @Mock
    private TimerService timerService;

    @Mock
    private MembershipListenerInterface membershipListener;

    @Mock
    private EntitiesManager entitiesManager;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private TimerUtility timerUtility;

    @Mock
    private CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    private EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Mock
    private TDPSUnpublishNotifier tdpsUnpublishNotifier;

    private final String statusUpdateSchedulerTime = "*,*,*,*,1,1,0";

    @Before
    public void startup() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
    }

    @Test
    public void testTimeout() {

        mockAllTheSchedulars();

        pkiManagerStatusUpdateTimerServiceBean.timeout(timer);

        verifyAllTheSchedulars();

    }

    @Test
    public void testTimeoutThrowsCertificateStatusUpdateFailedException() {
        doThrow(CertificateStatusUpdateFailedException.class).when(certificatePersistenceHelper).updateCertificateStatusToExpired();

        pkiManagerStatusUpdateTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
    }

    @Test
    public void testTimeoutThrowsCertificateStatusUpdateFailedExceptionFromApi() {
        doThrow(com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateStateChangeException.class).when(coreCertificateManagementService).updateCertificateStatusToExpired();

        pkiManagerStatusUpdateTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
    }

    @Test
    public void testTimeoutThrowsCRLServiceException() {
        doThrow(CRLServiceException.class).when(crlManager).updateCRLStatusToExpired();

        pkiManagerStatusUpdateTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
    }

    @Test
    public void testTimeoutThrowsException() {
        doThrow(Exception.class).when(crlManager).updateCRLStatusToExpired();

        pkiManagerStatusUpdateTimerServiceBean.timeout(timer);

        verify(logger).error(Matchers.anyString());
    }

    @Test
    public void testScheduleJob() {

        when(configurationListener.getStatusUpdateSchedulerTime()).thenReturn(statusUpdateSchedulerTime);

        pkiManagerStatusUpdateTimerServiceBean.scheduleJob();

        verify(configurationListener).getStatusUpdateSchedulerTime();
    }

    @Test
    public void testScheduleJobWithScheduleTimeAsNull() {

        when(configurationListener.getStatusUpdateSchedulerTime()).thenReturn(null);

        pkiManagerStatusUpdateTimerServiceBean.scheduleJob();

        verify(configurationListener).getStatusUpdateSchedulerTime();
    }

    @Test
    public void testScheduleJobException() {

        final String invalidTimer = "7868";

        when(configurationListener.getStatusUpdateSchedulerTime()).thenReturn(invalidTimer);

        pkiManagerStatusUpdateTimerServiceBean.scheduleJob();

        verify(configurationListener).getStatusUpdateSchedulerTime();
    }

    @Test
    public void testScheduleJobConfigurationPropertyNotFoundException() {
        doThrow(ConfigurationPropertyNotFoundException.class).when(configurationListener).getStatusUpdateSchedulerTime();

        pkiManagerStatusUpdateTimerServiceBean.scheduleJob();

        verify(configurationListener).getStatusUpdateSchedulerTime();
    }

    @Test
    public void testResetIntervalTimer() {

        pkiManagerStatusUpdateTimerServiceBean.resetIntervalTimer(statusUpdateSchedulerTime);

        verify(timerService).createCalendarTimer((ScheduleExpression) anyObject(), (TimerConfig) anyObject());

    }

    private void mockAllTheSchedulars() {
        doNothing().when(certificatePersistenceHelper).updateCertificateStatusToExpired();
        doNothing().when(coreCertificateManagementService).updateCertificateStatusToExpired();
        doNothing().when(crlManager).updateCRLStatusToExpired();
        doNothing().when(coreCRLManagementService).updateCRLStatusToExpired();
        doNothing().when(coreCRLManagementService).updateCRLStatusToInvalid();
        doNothing().when(entitiesManager).updateEntityStatusToInactive();
        doNothing().when(crlManager).deleteDuplicatesAndInsertLatestCRLs();
        doNothing().when(crlManager).unpublishInvalidCRLs();
    }

    private void verifyAllTheSchedulars() {
        verify(entitiesManager).updateEntityStatusToInactive();
        verify(certificatePersistenceHelper).updateCertificateStatusToExpired();
        verify(coreCertificateManagementService).updateCertificateStatusToExpired();
        verify(caCertificatePersistenceHelper).getExpiredCACertificatesToUnpublish();
        verify(entityCertificatePersistenceHelper).getExpiredEntityCertificatesToUnpublish();
        verify(crlManager).updateCRLStatusToExpired();
        verify(coreCRLManagementService).updateCRLStatusToExpired();
        verify(coreCRLManagementService).updateCRLStatusToInvalid();
        verify(crlManager).deleteDuplicatesAndInsertLatestCRLs();
        verify(crlManager).unpublishInvalidCRLs();
    }
}
