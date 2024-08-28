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

import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class fetches the corresponding CRLScheduler time value from PKIManagerConfigurationListener and triggers the scheduler at the corresponding time interval which in turn triggers the
 * getLatestCrl method at the particular time interval
 * 
 * @author xnagsow
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class GetLatestCRLTimerServiceBean {

    @Inject
    private TimerService timerService;

    @Inject
    private CRLManager crlManager;

    @Inject
    private Logger logger;

    @Inject
    private PKIManagerConfigurationListener configurationListener;

    @Inject
    MembershipListenerInterface membershipListener;

    @Inject
    SystemRecorder systemRecorder;

    private final AtomicBoolean isCRLSchedulerJobBusy = new AtomicBoolean(false);

    /**
     * This method will automatically trigger the job getLatestCRLs with respect to the time configured by the scheduler.
     * 
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {

        logger.debug("timeout method invoked in GetLatestCRLTimerServiceBean class");

        if (!isCRLSchedulerJobBusy.compareAndSet(false, true)) {
            logger.info("Previous timer {} is already running and waiting for next time out", TimerServiceConstants.GET_LATEST_CRL_TIMER_INFO);
            systemRecorder.recordError("PKIMANAGER.TIMER_SERVICE", ErrorSeverity.WARNING, "GetLatestCRLTimerServiceBean", "fetchLatestCRLsSchedulerTime", "Previous timer"
                    + TimerServiceConstants.GET_LATEST_CRL_TIMER_INFO + " is already running and waiting for next time out");
            return;
        }

        try {
            if (membershipListener.isMaster()) {
                crlManager.getLatestCRLs();
            }
        } catch (final Exception exception) {
            logger.debug("Error occured while fetching latest CRL job ", exception);
            logger.error(ErrorMessages.AUTOMATIC_FETCH_LATEST_CRL_JOB_FAILED + exception.getMessage());
            systemRecorder.recordError("PKIMANAGER.TIMER_SERVICE", ErrorSeverity.CRITICAL, "GetLatestCRLTimerServiceBean", "fetchLatestCRLsSchedulerTime",
                    ErrorMessages.AUTOMATIC_FETCH_LATEST_CRL_JOB_FAILED);
        } finally {
            isCRLSchedulerJobBusy.set(false);
        }

        logger.debug("End of timeout method in GetLatestCRLTimerServiceBean class");

    }

    /**
     * This Method is used to trigger the scheduler with the parameters configured in model.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.debug("ScheduleJob method invoked in GetLatestCRLTimerServiceBean class");

        try {
            final String fetchLatestCRLsSchedulerTime = configurationListener.getFetchLatestCRLsSchedulerTime();
            if (fetchLatestCRLsSchedulerTime != null) {
                createTimer(fetchLatestCRLsSchedulerTime);
            } else {
                logger.error(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name fetchLatestCRLsSchedulerTime. Could not schedule PKIManager GetLatestCRLTimerInfo Timer job");
                systemRecorder.recordError("PKIMANAGER.CONFIG_PROPERTY_NOT_FOUND", ErrorSeverity.CRITICAL, "GetLatestCRLTimerServiceBean", "fetchLatestCRLsSchedulerTime",
                        ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name fetchLatestCRLsSchedulerTime. Could not schedule PKIManager GetLatestCRLTimerInfo Timer job");
            }

        } catch (final ConfigurationPropertyNotFoundException configurationPropertyNotFoundException) {
            logger.debug("Error occured while fetching Configuration Property with name fetchLatestCRLsSchedulerTime ", configurationPropertyNotFoundException);
            logger.error(TimerServiceConstants.FAILED_TO_READ_CONFIGURATION_PARAMETER_VALUE, configurationPropertyNotFoundException.getMessage());
            systemRecorder.recordError("PKIMANAGER.TIMER_SERVICE", ErrorSeverity.CRITICAL, "GetLatestCRLTimerServiceBean", "fetchLatestCRLsSchedulerTime",
                    TimerServiceConstants.FAILED_TO_READ_CONFIGURATION_PARAMETER_VALUE);
        } catch (final Exception exception) {
            logger.debug("Error occured while scheduling PKIManager GetLatestCRLTimerInfo Timer ", exception);
            logger.error(TimerServiceConstants.FAILED_TO_START_GETLATESTCRL_SCHEDULER_JOB, exception.getMessage());
            systemRecorder.recordError("PKIMANAGER.TIMER_SERVICE", ErrorSeverity.CRITICAL, "GetLatestCRLTimerServiceBean", "fetchLatestCRLsSchedulerTime",
                    TimerServiceConstants.FAILED_TO_START_GETLATESTCRL_SCHEDULER_JOB);
        }

        logger.debug("End of ScheduleJob method invoked in GetLatestCRLTimerServiceBean class");
    }

    /**
     * This method is used to reset the timer configuration with newly changed configuration parameter value
     * 
     * @param newFetchLatestCRLsSchedulerTime
     *            is the parameter of newly changed configuration parameter value
     * @throws TimerException
     *             is thrown when failed to create or cancel an EJB timer.
     */
    public void resetIntervalTimer(final String newFetchLatestCRLsSchedulerTime) throws TimerException {
        logger.debug("Resetting interval timer for class {}. Setting interval to {}", this.getClass().getSimpleName(), newFetchLatestCRLsSchedulerTime);

        TimerUtility.cancelTimerByTimerConfig(timerService, TimerServiceConstants.GET_LATEST_CRL_TIMER_INFO);
        // TODO (TORF-164889)Configuration parameter validations will do in the next phase.
        createTimer(newFetchLatestCRLsSchedulerTime);

        logger.debug("End of resetIntervalTimer method invoked in GetLatestCRLTimerServiceBean class");
    }

    private void createTimer(final String schedulerTime) throws TimerException {
        TimerUtility.createTimer(timerService, schedulerTime, TimerServiceConstants.GET_LATEST_CRL_TIMER_INFO);
    }
}
