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
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.CertificateExpiryNotificationHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class schedules a timer service which fetches Entity certificate expiry details and sends alarm for the active/inactive certificates which are going to expire as per the configuration
 * 
 * @author tcsashc
 */

@Singleton
@Startup
public class EntityCertExpiryNotificationTimerServiceBean {

    @Inject
    private Logger logger;

    @Inject
    private TimerService timerService;

    @Inject
    CertificateExpiryNotificationHandler certificateExpiryNotificationHandler;

    @Inject
    PKIManagerConfigurationListener pKIManagerConfigurationListener;

    @Inject
    MembershipListenerInterface membershipListener;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method will automatically trigger the job to fetch the list of Active and Inactive entity Certificates which are about to expire in bellow Period Before Expiry.
     * 
     * @param timer
     *            Timer configured by the setTimer method
     */
    @Timeout
    public void timeout(final Timer timer) {
        logger.info("CertExpiryNotificationScheduler started to fetch active and inactive certificates of CA which are going to expire.");
        try {
            if (membershipListener.isMaster()) {
                logger.info("I'm master. Start of certificate expiry notification job.");
                certificateExpiryNotificationHandler.handle(EntityType.ENTITY);
                logger.info("End of certificate expiry notification job.");
            }
        } catch (Exception exception) {
            logger.error(ErrorMessages.CERT_EXPIRY_NOTIFICATION_JOB_FAILED, exception.getMessage());
            logger.debug(ErrorMessages.CERT_EXPIRY_NOTIFICATION_JOB_FAILED, exception);
            systemRecorder.recordSecurityEvent("Certificate Expiry Timer Service", "EntityCertExpiryNotificationTimerService", "Certificate expiry notification scheduler job has been failed.",
                    "EntityCertExpiryNotificationTimerService.timeout", ErrorSeverity.CRITICAL, "FAILURE");
        }
    }

    /**
     * This method sets the timer for the scheduler job
     */

    @PostConstruct
    public void setTimer() {
        logger.debug("Setting the timer for entity CertExpiryNotificationScheduler job.");
        try {
            final String entityCertExpiryNotifySchedulerTime = pKIManagerConfigurationListener.getEntityCertExpiryNotifySchedulerTime();
            if (entityCertExpiryNotifySchedulerTime != null) {
                TimerUtility.createTimer(timerService, entityCertExpiryNotifySchedulerTime, TimerServiceConstants.CERT_EXPIRY_NOTIFICATION_SCHEDULER_INFO);
                logger.debug("End of set timer method in entityCertExpiryNotifySchedulerTime.");
            } else {
                logger.error("{} with name entityCertExpiryNotifySchedulerTime. Could not schedule PKIManager EntityCertExpiryNotification job.", ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL);
            }
        } catch (TimerException timerException) {
            logger.error("Could not schedule Entity CertExpiryNotificationScheduler job ", timerException.getMessage());
            logger.debug("Could not schedule Entity CertExpiryNotificationScheduler job ", timerException);
            systemRecorder.recordSecurityEvent("Certificate Expiry Timer Service", "EntityCertExpiryNotificationTimerService", "Failed to schedule EntityCertExpiryNotificationr job.",
                    "EntityCertExpiryNotificationTimerService.setTimer", ErrorSeverity.CRITICAL, "FAILURE");
        }

    }
}
