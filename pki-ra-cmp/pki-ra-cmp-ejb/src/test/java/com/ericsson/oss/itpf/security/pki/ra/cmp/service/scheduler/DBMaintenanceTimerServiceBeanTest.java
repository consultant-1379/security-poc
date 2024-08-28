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
package com.ericsson.oss.itpf.security.pki.ra.cmp.service.scheduler;

import javax.ejb.Timer;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.RevocationHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.scheduler.DBCleanUpHandler;;

@RunWith(MockitoJUnitRunner.class)
public class DBMaintenanceTimerServiceBeanTest {

    @InjectMocks
    DBMaintenanceTimerServiceBean dbMaintenanceTimerServiceBean;

    @Mock
    Logger logger;

    @Mock
    DBCleanUpHandler dBCleanUpService;

    @Mock
    RevocationHandler revocationHandler;

    @Mock
    ConfigurationParamsListener configurationParamsListener;

    @Mock
    SystemRecorder systemRecorder;

    private Timer timer;

    @Test
    public void testTimeout() {
        dbMaintenanceTimerServiceBean.timeout(timer);
        Mockito.verify(dBCleanUpService).cleanUpDB();
    }

    @Test
    public void testSceduleJob() {
        Mockito.when(configurationParamsListener.getDbMaintenanceSchedulerInterval()).thenReturn(null);
        dbMaintenanceTimerServiceBean.scheduleJob();
    }

    @Test
    public void testTimeoutException() {
        Mockito.doThrow(Exception.class).when(revocationHandler).revokeCertificateBasedOnStatus();
        dbMaintenanceTimerServiceBean.timeout(timer);
        Mockito.verify(logger).error("Exception occured in DBMaintenanceTimerServiceBean during database cleanup");
    }

}
