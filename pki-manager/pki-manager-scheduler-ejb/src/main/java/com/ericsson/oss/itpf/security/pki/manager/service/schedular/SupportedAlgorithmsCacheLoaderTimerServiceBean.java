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

import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SupportedAlgorithmsCacheOperations;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class will trigger the job to load supported algorithms cache at a particular time interval defined by schedulerTime.These algorithms will be used by the SCEP and CMP service during the
 * certificate request validation.
 * 
 * @author xchowja
 */
@Singleton
@Startup
public class SupportedAlgorithmsCacheLoaderTimerServiceBean {

    @Inject
    MembershipListenerInterface membershipListenerInterface;

    @Inject
    Logger logger;

    @EJB
    SupportedAlgorithmsCacheOperations supportedAlgorithmsCacheOperations;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    TimerService timerService;

    private final String schedulerTime = TimerServiceConstants.DEFAULT_SCHEDULER_TIME_FOR_SUPPORTED_ALGORITHMS_CACHE;
    private final AtomicBoolean isSupportedAlgorithmsCache = new AtomicBoolean(false);

    /**
     * This method will automatically trigger the job at the specified time intervals to load supported algorithms cache .
     * 
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {

        if (!isSupportedAlgorithmsCache.compareAndSet(false, true)) {
            logger.info("Previous timer {} is still running and waiting for next time out", TimerServiceConstants.SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER_SERVICE_INFO);
            systemRecorder.recordError("PKI_MANAGER.TIMER_SERVICE", ErrorSeverity.INFORMATIONAL, "SupportedAlgorithmsCacheLoaderTimerServiceBean", "Loading Supported Algorithms cache",
                    "Previous timer" + TimerServiceConstants.SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER_SERVICE_INFO + " is still running and waiting for next time out");
            return;
        }
        try {
            final boolean isMaster = membershipListenerInterface.isMaster();
            logger.info("This is MASTER {}", isMaster);
            if (isMaster) {
                logger.info("timeout method is triggered in SupportedAlgorithmsCacheLoaderTimerServiceBean class");
                supportedAlgorithmsCacheOperations.load();
                logger.info("Supported Algorithms cache is loaded with algorithms successfully. Hence, canceling the timer");
                TimerUtility.cancelTimerByTimerConfig(timerService, TimerServiceConstants.SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER_SERVICE_INFO);
            }
        } catch (final TimerException timerException) {
            logger.error(TimerServiceConstants.FAILED_TO_CANCEL_TIMER);
            logger.debug(TimerServiceConstants.FAILED_TO_CANCEL_TIMER, timerException);
            systemRecorder.recordError("SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER.CANCELING_TIMER_JOB_FAILURE", ErrorSeverity.CRITICAL, "SupportedAlgorithmsCacheLoaderTimerServiceBean",
                    "Cancelling of Supported Algorithms cache loader timer", TimerServiceConstants.FAILED_TO_CANCEL_TIMER + timerException.getMessage());
        } catch (final Exception e) {
            logger.debug(TimerServiceConstants.FAILED_TO_LOAD_SUPPORTED_ALGORITHMS_CACHE + e);
            logger.error(TimerServiceConstants.FAILED_TO_LOAD_SUPPORTED_ALGORITHMS_CACHE + e.getMessage());
            systemRecorder.recordError("SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER.CANCELING_TIMER_JOB_FAILURE", ErrorSeverity.CRITICAL, "SupportedAlgorithmsCacheLoaderTimerServiceBean",
                    "Loading Supported Algorithms cache", TimerServiceConstants.FAILED_TO_LOAD_SUPPORTED_ALGORITHMS_CACHE + e.getMessage());
        } finally {
            isSupportedAlgorithmsCache.set(false);
        }
        logger.info("End of timeout method in SupportedAlgorithmsCacheLoaderTimerServiceBean class");
    }

    /**
     * This Method is used to trigger the scheduler with all the parameters configured.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.info("ScheduleJob method started in SupportedAlgorithmsCacheLoaderTimerServiceBean class");
        try {
            TimerUtility.createTimer(timerService, schedulerTime, TimerServiceConstants.SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER_SERVICE_INFO);
        } catch (final Exception exception) {
            logger.error("Could not schedule PKIMANAGER supported algorithms cache loader Scheduler job: {}", exception.getMessage());
            logger.debug("Could not schedule PKIMANAGER supported algorithms cache loader Scheduler job: {}", exception);
            systemRecorder.recordError("PKI_MANAGER_SERVICE_STARTUP.TIMER_SERVICE_FAILED", ErrorSeverity.CRITICAL, "PKI_MANAGER_SERVICE.TIMER_SERVICE", "SUPPORTED_ALGORITHMS_CACHE_LOADER_SCHEDULER",
                    TimerServiceConstants.FAILED_TO_START_SUPPORTED_ALGORITHMS_CACHE_LOADER_SCHEDULER_JOB);
        }
        logger.info("End of scheduleJob method in SupportedAlgorithmsCacheLoaderTimerServiceBean class");
    }

}
