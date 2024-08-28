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

package com.ericsson.oss.itpf.security.pki.manager.service.schedular;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
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
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.ExternalCACRLHandler;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class fetches the corresponding ExternalCACRLScheduler time value from PKIManagerConfigurationListener and triggers the scheduler at the corresponding time interval which in turn triggers the
 * getExternalCACrl method at the particular time interval
 * 
 * @author xvekkar
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class ExternalCACRLTimerServiceBean {

    @Inject
    private TimerService timerService;

    @Inject
    private ExternalCACRLHandler externalCACRLHandler;

    @Inject
    private Logger logger;

    @Inject
    private PKIManagerConfigurationListener configurationListener;

    @Inject
    private MembershipListenerInterface membershipListener;

    @Inject
    private SystemRecorder systemRecorder;

    private boolean is_timer_running = false;

    /**
     * This method will automatically trigger the job externalCACRLs with respect to the time configured by the scheduler.
     * 
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {
        if (!is_timer_running && membershipListener.isMaster()) {
            logger.info("Timeout method triggerd in ExternalCACRLTimerServiceBean class in Master service.");
            is_timer_running = true;
            logger.debug("timeout method invoked in ExternalCACRLTimerServiceBean class.");
            try {
                externalCACRLHandler.externalCACRLHandle();
                is_timer_running = false;
            } catch (Exception e) {
                logger.error(ErrorMessages.AUTOMATIC_FETCH_EXTERNAL_CA_CRL_JOB_FAILED + e.getMessage());
                logger.debug(ErrorMessages.AUTOMATIC_FETCH_EXTERNAL_CA_CRL_JOB_FAILED, e);
                systemRecorder.recordSecurityEvent("External CA CRL Timer Service", "ExternalCACRLTimerServiceBean", "External CA CRL update scheduler job has been failed.",
                        "ExternalCACRLTimerServiceBean.timeout", ErrorSeverity.CRITICAL, "FAILURE");
            }
            is_timer_running = false;
            logger.debug("End of timeout method in ExternalCACRLTimerServiceBean class.");
        } else {
            logger.debug("Privious timer {} is already running and waiting for next time out", TimerServiceConstants.EXTERNAL_CA_CRL_TIMER_INFO);
        }
    }

    /**
     * This Method is used to trigger the scheduler with the parameters configured in model.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.debug("ScheduleJob method has been invoked in externalCACRLTimerServiceBean class.");
        try {
            final String externalCACRLsSchedulerTime = configurationListener.getExternalCACRLsSchedulerTime();
            if (externalCACRLsSchedulerTime != null) {
                TimerUtility.createTimer(timerService, externalCACRLsSchedulerTime, TimerServiceConstants.EXTERNAL_CA_CRL_TIMER_INFO);
                logger.debug("End of scheduleJob method in ExternalCACRLTimerServiceBean class.");
            } else {
                logger.error("{} with name externalCACRLsSchedulerTime. Could not schedule PKIManager ExternalCACRLs job.", ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL);
            }
        } catch (TimerException e) {
            logger.error("Could not schedule  PKIManager ExternalCACRLs Timer job {}", e.getMessage());
            logger.debug("Could not schedule  PKIManager ExternalCACRLs Timer job ", e);
            systemRecorder.recordSecurityEvent("External CA CRL Timer Service", "ExternalCACRLTimerServiceBean", "Could not schedule PKIManager ExternalCACRLs Timer job.",
                    "ExternalCACRLTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (ConfigurationPropertyNotFoundException e) {
            logger.error("{} with name ExternalCACRLsSchedulerTime. Could not schedule PKIManager ExternalCACRLs Timer job.", ErrorMessages.CONFIGURATION_PROPERTY_NOT_FOUND);
            logger.debug(ErrorMessages.CONFIGURATION_PROPERTY_NOT_FOUND, e);
            systemRecorder.recordSecurityEvent("External CA CRL Timer Service", "ExternalCACRLTimerServiceBean", "Could not schedule PKIManager ExternalCACRLs Timer job.",
                    "ExternalCACRLTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
        }
    }
}
