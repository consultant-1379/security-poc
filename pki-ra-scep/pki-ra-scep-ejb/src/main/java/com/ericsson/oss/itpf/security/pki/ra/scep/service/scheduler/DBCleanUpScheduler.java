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
package com.ericsson.oss.itpf.security.pki.ra.scep.service.scheduler;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.processor.DBCleanUpProcessor;
import com.ericsson.oss.itpf.security.pki.ra.scep.service.cluster.MembershipListenerInterface;

/**
 * This class fetches the corresponding scepDBCleanupSchedulerTime value from scepConfigurationListener and triggers the scheduler at the corresponding time interval which in turn triggers the
 * cleanupScepDB method at the particular time interval
 * 
 * @author xnagsow
 */
@Singleton
@Startup
public class DBCleanUpScheduler {

    @Inject
    private TimerService timerService;

    @Inject
    private DBCleanUpProcessor dbCleanUpProcessor;

    @Inject
    private ConfigurationListener configurationListener;

    @Inject
    private Logger logger;

    @Inject
    private MembershipListenerInterface membershipListener;

    @Inject
    private SystemRecorder systemRecorder;

    private final AtomicBoolean isScepDBCleanupJobBusy = new AtomicBoolean(false);

    /**
     * This method will be triggered at configured time intervals and perform the following tasks: 1.Checks whether job is already running or not. 2.Starts executing cleanupScepDB method to clean the
     * records which are older than a configured period in SCEP db.
     * 
     * @param timer
     *            An object of Timer which is configured by the schedule job
     */
    @Timeout
    public void timeout(final Timer timer) {
        if (!isScepDBCleanupJobBusy.compareAndSet(false, true)) {
            logger.warn(ErrorMessages.PREVIOUS_TIMER_IS_ALREADY_RUNNING);
            systemRecorder.recordError("PKIRASCEP.TIMER_SERVICE", ErrorSeverity.WARNING, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS", ErrorMessages.PREVIOUS_TIMER_IS_ALREADY_RUNNING);
            return;
        }
        logger.info("Timeout method trigered in DBCleanUpScheduler class");
        try {
            if (membershipListener.isMaster()) {
                logger.info("I am master , PKIRASCEPService");
                final int scepRequestRecordPurgePeriod = configurationListener.getScepRequestRecordPurgePeriod();
                dbCleanUpProcessor.cleanUpOldRecordsFromSCEPDB(scepRequestRecordPurgePeriod);
                logger.info("Scep DB cleanup job is completed successfully");
            }
        } catch (final ConfigurationPropertyNotFoundException configurationPropertyNotFoundException) {
            logger.error(ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_REQUEST_RECORD_PURGE_PERIOD_VALUE, configurationPropertyNotFoundException.getMessage());
            logger.debug(ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_REQUEST_RECORD_PURGE_PERIOD_VALUE, configurationPropertyNotFoundException);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS",
                    ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_REQUEST_RECORD_PURGE_PERIOD_VALUE + configurationPropertyNotFoundException.getMessage());
        } catch (final Exception exception) {
            logger.error("Exception occured in DBCleanUpScheduler during SCEP DB cleanup job : {}", exception.getMessage());
            logger.debug("Exception occured in DBCleanUpScheduler during SCEP DB cleanup job  : {}", exception);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS",
                    "Error occured while doing SCEP DB cleanup job." + exception.getMessage());
        } finally {
            isScepDBCleanupJobBusy.set(false);
        }
        logger.info("End of timeout method in DBCleanUpScheduler class");
    }

    /**
     * This Method will schedule the timer service by using the parameters configured in model to perform SCEP DB clean up task.
     */
    @PostConstruct
    public void scheduleJob() {

        logger.info("ScheduleJob method in DBCleanUpScheduler class");
        try {
            final String schedulerTime = configurationListener.getScepDBCleanupSchedulerTime();
            if (schedulerTime != null) {
                TimerUtility.createTimer(timerService, schedulerTime, Constants.DB_CLEANUP_SCHEDULER_INFO);
            } else {
                logger.error(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name " + Constants.DB_CLEANUP_SCHEDULER_INFO + ". Could not start PKIRASCEP DB cleanup scheduler job due to");
                systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS",
                        ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL);
            }
        } catch (final ConfigurationPropertyNotFoundException configurationPropertyNotFoundException) {
            logger.error(ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_DB_CLEANUP_SCHEDULER_TIME_VALUE, configurationPropertyNotFoundException.getMessage());
            logger.debug(ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_DB_CLEANUP_SCHEDULER_TIME_VALUE, configurationPropertyNotFoundException);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS",
                    ErrorMessages.FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_DB_CLEANUP_SCHEDULER_TIME_VALUE);
        } catch (final Exception exception) {
            logger.error("Could not start PKIRASCEP DB cleanup job due to : {}", exception.getMessage());
            logger.debug("Could not start PKIRASCEP DB cleanup job due to : {}", exception);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBCleanUpScheduler", "PURGING_OF_OLD_DB_RECORDS",
                    "Could not start PKIRASCEP DB cleanup job due to : " + exception.getMessage());
        }

        logger.info("End of scheduleJob method in DBCleanUpScheduler class");
    }
}
