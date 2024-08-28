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
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.RevocationHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.timer.constants.TimerServiceConstants;

/**
 * This class fetches the corresponding scheduler time value from ConfigurationParamsListener and triggers the scheduler at the corresponding time
 * interval which in turn triggers the cleanupDB and RevokeCertificates method at the particular time interval.
 * 
 * @author tcsramc
 */
@Singleton
@Startup
public class DBMaintenanceTimerServiceBean {

    @Inject
    TimerService timerService;

    @Inject
    DBCleanUpHandler dBCleanUpService;

    @Inject
    RevocationHandler revocationHandler;

    @Inject
    ConfigurationParamsListener configurationParamsListener;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    private String schedulerTime;

    /**
     * This Method is used to trigger cleanUpDB and revokeCertificateBasedOnStatus methods with respect to the time configured by the scheduler.
     * 
     * @param timer
     */
    @Timeout
    public void timeout(final Timer timer) {
        logger.info("timeout method in DbcleanupScheduler class");
        try {
            dBCleanUpService.cleanUpDB();
            revocationHandler.revokeCertificateBasedOnStatus();
        } catch (final Exception exception) {
            logger.debug("Exception occured in DBMaintenanceTimerServiceBean during database cleanup  : ", exception);
            logger.error("Exception occured in DBMaintenanceTimerServiceBean during database cleanup");
            systemRecorder.recordError("PKIRA.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.DBMaintenanceTimerService", "PURGING_OF_DB_OLD_RECORDS_AND_REVOCATION_OF_INVALID_CERTS",
                    "Exception occured in DBMaintenanceTimerServiceBean during database cleanup " + exception.getMessage());
        }
        logger.info("End of timeout method in DbcleanupScheduler class");
    }

    /**
     * This Method is used to trigger the scheduler with all the parameters configured.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.info("ScheduleJob method in DbcleanupScheduler class");
        try {
            schedulerTime = configurationParamsListener.getDbMaintenanceSchedulerInterval();
            createTimer(schedulerTime);

        } catch (final ConfigurationPropertyNotFoundException configurationPropertyNotFoundException) {
            logger.error("Configuration Property Not found with name dbMaintenanceSchedulerInterval",
                    configurationPropertyNotFoundException.getMessage());
            logger.debug("Configuration Property Not found with name dbMaintenanceSchedulerInterval ", configurationPropertyNotFoundException);
            systemRecorder.recordError("PKIRA.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBMaintenanceTimerService", "PURGING_OF_DB_OLD_RECORDS_AND_REVOCATION_OF_INVALID_CERTS",
                    "Could not schedule PKIRA CMP DB maintenance Scheduler job " + configurationPropertyNotFoundException.getMessage());
        } catch (final Exception exception) {
            logger.error("Could not schedule PKIRA CMP DB maintenance Scheduler job: {}", exception.getMessage());
            logger.debug("Could not schedule PKIRA CMP DB maintenance Scheduler job ", exception);
            systemRecorder.recordError("PKIRA.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKIRA.DBMaintenanceTimerService", "PURGING_OF_DB_OLD_RECORDS_AND_REVOCATION_OF_INVALID_CERTS",
                    "Could not schedule PKIRA CMP DB maintenance Scheduler job " + exception.getMessage());
        }

        logger.info("End of scheduleJob method in DbcleanupScheduler class");
    }

    /**
     * This method is used to reset the timer configuration with newly changed configuration parameter value
     *
     * @param newDbMaintenanceSchedulerInterval
     *            is the parameter of newly changed configuration parameter value
     */
    public void resetIntervalTimer(final String newDbMaintenanceSchedulerInterval) {
        logger.info("Resetting interval timer for class {}. Setting interval to {}", this.getClass().getSimpleName(),
                newDbMaintenanceSchedulerInterval);

        TimerUtility.cancelTimerByTimerConfig(timerService, TimerServiceConstants.DB_MAINTENANCE_TIMER_SERVICE_INFO);
        createTimer(newDbMaintenanceSchedulerInterval);

        logger.info("End of resetIntervalTimer method invoked in DBMaintenanceTimerServiceBean class");
    }

    private void createTimer(final String schedulerTime) {
        TimerUtility.createTimer(timerService, schedulerTime, TimerServiceConstants.DB_MAINTENANCE_TIMER_SERVICE_INFO);
    }
}
