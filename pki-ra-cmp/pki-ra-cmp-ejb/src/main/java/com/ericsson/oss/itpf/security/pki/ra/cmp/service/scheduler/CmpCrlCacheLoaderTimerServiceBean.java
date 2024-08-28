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

import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPCrlCacheLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.timer.constants.TimerServiceConstants;

/**
 * This class will trigger the job to load pki-ra-cmp CRL cache at a particular time interval defined by schedulerTime.
 *
 * @author xnagsow
 */
@Singleton
@Startup
public class CmpCrlCacheLoaderTimerServiceBean {

    @Inject
    Logger logger;

    @Inject
    TimerService timerService;

    @Inject
    MembershipListenerInterface membershipListenerInterface;

    @Inject
    private SystemRecorder systemRecorder;

    private final ServiceFinderBean serviceFinder = new ServiceFinderBean();

    private static final String SCHEDULER_TIME = TimerServiceConstants.DEFAULT_SCHEDULER_TIME_FOR_CMP_CRL_CACHE_LOADER_SCHEDULER;
    private final AtomicBoolean isCmpCrlCacheLoaderSchedulerBusy = new AtomicBoolean(false);

    /**
     * This method will automatically trigger the job at the specified time intervals to load pki-ra-cmp CRL cache .
     *
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {

        if (!isCmpCrlCacheLoaderSchedulerBusy.compareAndSet(false, true)) {
            logger.info("Previous timer {} is already running and waiting for next time out",
                    TimerServiceConstants.CMP_CRL_CACHE_LOADER_TIMER_SERVICE_INFO);
            systemRecorder.recordError("PKIRACMP.TIMER_SERVICE", ErrorSeverity.WARNING, "CMPCRLCacheLoaderTimerServiceBean", "Loading CMP Crl cache",
                    "Previous timer"
                            + TimerServiceConstants.CMP_CRL_CACHE_LOADER_TIMER_SERVICE_INFO + " is already running and waiting for next time out");
            return;
        }
        try {
            if (membershipListenerInterface.isMaster()) {
                logger.info("timeout method is triggered in CMPCRLCacheLoaderTimerServiceBean class");

                final CMPCrlCacheLocalService crlCacheLocalService = serviceFinder.find(CMPCrlCacheLocalService.class);
                crlCacheLocalService.initialiseCRLCache();
                }
                logger.info("Cancelling the timer CmpCrlCacheLoaderTimerServiceInfo");
                TimerUtility.cancelTimerByTimerConfig(timerService, TimerServiceConstants.CMP_CRL_CACHE_LOADER_TIMER_SERVICE_INFO);

        } catch (final TimerException e) {
            logger.error(TimerServiceConstants.FAILED_TO_CANCEL_TIMER, TimerServiceConstants.CMP_CRL_CACHE_LOADER_TIMER_SERVICE_INFO);
            logger.debug("Failed to cancel the timer CmpCrlCacheLoaderTimerServiceInfo ", e);
            systemRecorder.recordError("CMP_CRL_CACHE_LOADER_TIMER.CANCELING_TIMER_JOB_FAILURE", ErrorSeverity.CRITICAL,
                    "CMPCRLCacheLoaderTimerServiceBean",
                    "Canceling of Cmp Crl cache loader timer", TimerServiceConstants.FAILED_TO_CANCEL_TIMER + e.getMessage());
        } catch (final Exception e) {
            logger.debug(TimerServiceConstants.FAILED_TO_INTIALIZE_CMP_CRL_CACHE + e);
            logger.error(TimerServiceConstants.FAILED_TO_INTIALIZE_CMP_CRL_CACHE + e.getMessage());
            systemRecorder.recordError("CMP_CRL_CACHE_LOADER_TIMER.LOADING CMP_CRL_CACHE_FAILURE", ErrorSeverity.CRITICAL,
                    "CMPCRLCacheLoaderTimerServiceBean",
                    "Loading Cmp Crl cache", TimerServiceConstants.FAILED_TO_INTIALIZE_CMP_CRL_CACHE + e.getMessage());
        } finally {
            isCmpCrlCacheLoaderSchedulerBusy.set(false);
        }
        logger.info("End of timeout method in CMPCRLCacheLoaderTimerServiceBean class");
    }

    /**
     * This Method is used to trigger the scheduler with all the parameters configured.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.info("ScheduleJob method started in CMPCRLCacheLoaderTimerServiceBean class");
        try {
            TimerUtility.createTimer(timerService, SCHEDULER_TIME, TimerServiceConstants.CMP_CRL_CACHE_LOADER_TIMER_SERVICE_INFO);
        } catch (final Exception exception) {
            logger.error("Could not schedule PKIRACmp CRL cache loader Scheduler job: {}", exception.getMessage());
            logger.debug("Could not schedule PKIRACmp CRL cache loader Scheduler job: ", exception);
            systemRecorder.recordError("CMP_SERVICE_STARTUP.TIMER_SERVICE_FAILED", ErrorSeverity.CRITICAL, "CMP_SERVICE.TIMER_SERVICE",
                    "CMP_CRL_CACHE_LOADER_SCHEDULER",
                    TimerServiceConstants.FAILED_TO_START_CMP_CRL_CACHE_LOADER_SCHEDULER_JOB);
        }
        logger.info("End of scheduleJob method in CMPCRLCacheLoaderTimerServiceBean class");
    }
}
