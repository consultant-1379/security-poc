/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.service.scheduler;

import static org.mockito.internal.verification.VerificationModeFactory.times;

import javax.ejb.Timer;
import javax.ejb.TimerService;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.processor.DBCleanUpProcessor;
import com.ericsson.oss.itpf.security.pki.ra.scep.service.cluster.MembershipListenerInterface;

/**
 * This class will test DBCleanUpScheduler class
 */
@RunWith(MockitoJUnitRunner.class)
public class DBCleanUpSchedulerTest {

    @InjectMocks
    private DBCleanUpScheduler dBCleanupScheduler;

    @Mock
    private TimerService timerService;

    @Mock
    private DBCleanUpProcessor dbCleanUpProcessor;

    @Mock
    private ConfigurationListener configurationListener;

    @Mock
    private Timer timer;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private MembershipListenerInterface membershipListener;

    /**
     * This method tests the timeout method of DBCleanUpScheduler
     */
    @Test
    public void testTimeout() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        dBCleanupScheduler.timeout(timer);
        Mockito.verify(dbCleanUpProcessor, times(1)).cleanUpOldRecordsFromSCEPDB(configurationListener.getScepRequestRecordPurgePeriod());
        Mockito.verify(logger).info("Scep DB cleanup job is completed successfully");
        Mockito.verify(logger).info("End of timeout method in DBCleanUpScheduler class");
    }

    /**
     * This method tests the timeout method of DBCleanUpScheduler for ConfigurationPropertyNotFoundException
     */
    @Test
    public void testTimeout_ConfigurationPropertyNotFoundException() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        Mockito.when(configurationListener.getScepRequestRecordPurgePeriod()).thenThrow(new ConfigurationPropertyNotFoundException(""));
        dBCleanupScheduler.timeout(timer);
        Mockito.verify(logger).error(ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_REQUEST_RECORD_PURGE_PERIOD_VALUE,
                "Was not able to find configuration property with name ''. Did you model it? Are all the models deployed correctly?");
        Mockito.verify(logger).info("End of timeout method in DBCleanUpScheduler class");
    }

    /**
     * This method tests the timeout method of DBCleanUpScheduler for RuntimeException
     */
    @Test
    public void testTimeout_RuntimeException() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        Mockito.when(configurationListener.getScepRequestRecordPurgePeriod()).thenThrow(new RuntimeException(""));
        dBCleanupScheduler.timeout(timer);
        Mockito.verify(logger).error("Exception occured in DBCleanUpScheduler during SCEP DB cleanup job : {}", "");
    }

    /**
     * This method tests the scheduleJob method
     */
    @Test
    public void testScheduleJob() {
        Mockito.when(configurationListener.getScepDBCleanupSchedulerTime()).thenReturn(JUnitConstants.scepDBCleanupSchedulerTime);
        dBCleanupScheduler.scheduleJob();
        Mockito.verify(logger).info("End of scheduleJob method in DBCleanUpScheduler class");

    }

    /**
     * This method tests the scheduleJob method of DBCleanUpScheduler for PkiScepServiceException when model is not properly configured
     */
    @Test
    public void testScheduleJob_ConfigurationPropertyNotFoundException() {
        Mockito.doThrow(ConfigurationPropertyNotFoundException.class).when(configurationListener).getScepDBCleanupSchedulerTime();
        dBCleanupScheduler.scheduleJob();
        Mockito.verify(systemRecorder).recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS",
                ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_DB_CLEANUP_SCHEDULER_TIME_VALUE);
    }

    /**
     * This method tests the scheduleJob method of DBCleanUpScheduler for RuntimeException
     */
    @Test
    public void testScheduleJob_RuntimeException() {
        Mockito.doThrow(new RuntimeException("Exception at runtime")).when(configurationListener).getScepDBCleanupSchedulerTime();
        dBCleanupScheduler.scheduleJob();
        Mockito.verify(logger).error("Could not start PKIRASCEP DB cleanup job due to : {}", "Exception at runtime");

    }

    /**
     * This method tests the scheduleJob method of DBCleanUpScheduler for PkiScepServiceException when null value passed for configuration parameter scehdulerTime
     */
    @Test
    public void testScheduleJob_With_Null_Value_For_ConfigParam() {
        Mockito.when(configurationListener.getScepDBCleanupSchedulerTime()).thenReturn(null);
        dBCleanupScheduler.scheduleJob();
        Mockito.verify(logger).error(
                ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name " + Constants.DB_CLEANUP_SCHEDULER_INFO + ". Could not start PKIRASCEP DB cleanup scheduler job due to");
        Mockito.verify(logger).info("End of scheduleJob method in DBCleanUpScheduler class");
    }
}
