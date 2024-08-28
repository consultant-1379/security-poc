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
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.config.change.event.listener.PkiManagerConfigChangeEventListener;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class will trigger the job to generate the pki-manager credentials at a particular time interval defined by schedulerTime.
 * 
 * @author xnagsow
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class PkiCredentialsManagementTimerServiceBean {

    @Inject
    private TimerService timerService;

    @Inject
    private CredentialsManager credentialsManager;

    @Inject
    PkiManagerConfigChangeEventListener pkiManagerConfigChangeEventListener;

    @Inject
    PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Inject
    private Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    private final String schedulerTime = TimerServiceConstants.DEFAULT_SCHEDULER_TIME_FOR_PKI_MANAGER_CREDM;
    private boolean is_timer_running = false;

    /**
     * This method will automatically trigger the job at the specified time intervals to generate the pki-manager credentials .
     * 
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {

        if (!is_timer_running) {
            is_timer_running = true;
            logger.info("timeout method invoked in PkiCredentialsManagementTimerServiceBean class.");

            try {
                credentialsManager.generatePkiCredentials();
                logger.info("Pki credentials generated successfully. Rescheduling the timer.");
                final String pkiManagerCredentialsManagementSchedulerTime = pkiManagerConfigurationListener.getPkiManagerCredentialsManagementSchedulerTime();
                if (pkiManagerCredentialsManagementSchedulerTime != null) {
                    TimerUtility.cancelTimerByTimerConfig(timerService, TimerServiceConstants.PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO);
                    TimerUtility.createTimer(timerService, pkiManagerCredentialsManagementSchedulerTime, TimerServiceConstants.PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO);
                    logger.debug(TimerServiceConstants.PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO, " rescheduled to {}.", pkiManagerCredentialsManagementSchedulerTime);
                }
            } catch (final TimerException | ConfigurationPropertyNotFoundException e) {
                logger.debug("Error occured while recreating timer for the changed configuration parameter ", e);
                logger.error(ErrorMessages.FAILED_TO_RECREATE_TIMER, TimerServiceConstants.PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO);
                systemRecorder.recordSecurityEvent("Credential Manager Timer Service", "PkiCredentialsManagementTimerServiceBean", "PKI Credential Manager scheduler job has been failed.",
                        "PkiCredentialsManagementTimerServiceBean.timeout", ErrorSeverity.CRITICAL, "FAILURE");
            } catch (final Exception e) {
                logger.debug("Error occured while getting pki credentials management job details ", e);
                logger.error(ErrorMessages.AUTOMATIC_PKI_CREDEM_MGMT_JOB_FAILED + e.getMessage());
                systemRecorder.recordSecurityEvent("Credential Manager Timer Service", "PkiCredentialsManagementTimerServiceBean", "PKI Credential Manager scheduler job has been failed.",
                        "PkiCredentialsManagementTimerServiceBean.timeout", ErrorSeverity.CRITICAL, "FAILURE");
            }
            is_timer_running = false;
            logger.info("End of timeout method in PkiCredentialsManagementTimerServiceBean class.");
        } else {
            logger.debug("Privious timer {} is already running and waiting for next time out.", TimerServiceConstants.PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO);
        }
    }

    /**
     * This Method is used to configure the timer for the given scheduler time.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.debug("ScheduleJob method invoked in PkiCredentialsManagementTimerServiceBean class.");
        try {
            TimerUtility.createTimer(timerService, schedulerTime, TimerServiceConstants.PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO);
        } catch (final TimerException e) {
            logger.debug("Error occured while scheduling  PKIManager getPkiCredentialCerts Timer job ", e);
            logger.error("Could not schedule  PKIManager getPkiCredentialCerts Timer job ", e.getMessage());
            systemRecorder.recordSecurityEvent("Credential Manager Timer Service", "PkiCredentialsManagementTimerServiceBean", "Could not schedule PKIManager getPkiCredentialCerts job.",
                    "PkiCredentialsManagementTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (final ConfigurationPropertyNotFoundException e) {
            logger.debug("Error occured while scheduling pkiManagerCredentialsManagementSchedulerTimeNot ", e);
            logger.error("{} with name pkiManagerCredentialsManagementSchedulerTime. Could not schedule PKIManager getPkiCredentialCerts job.", ErrorMessages.CONFIGURATION_PROPERTY_NOT_FOUND);
            systemRecorder.recordSecurityEvent("Credential Manager Timer Service", "PkiCredentialsManagementTimerServiceBean", "Could not schedule PKIManager getPkiCredentialCerts job.",
                    "PkiCredentialsManagementTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
        }
        logger.debug("End of scheduleJob method in PkiCredentialsManagementTimerServiceBean class.");
    }
}
