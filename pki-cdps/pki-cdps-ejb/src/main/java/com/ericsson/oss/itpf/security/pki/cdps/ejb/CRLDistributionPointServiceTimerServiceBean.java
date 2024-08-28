package com.ericsson.oss.itpf.security.pki.cdps.ejb;

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
//package com.ericsson.oss.itpf.security.pki.ra.scep.ejb;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationRequestMessage;
import com.ericsson.oss.itpf.security.pki.cdps.service.cluster.PKIRAMembershipListener;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;

/**
 * This class triggers the scheduler at the corresponding time interval to get the CRL's from pki-manager to publish or unpublish .
 * 
 * @author xchowja
 */
@Startup
@Singleton
public class CRLDistributionPointServiceTimerServiceBean {

    @Inject
    private TimerService timerService;

    @Inject
    @Modeled
    private EventSender<CRLNotificationRequestMessage> crlNotificationRequestMessage;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private PKIRAMembershipListener pkiraMembershipListener;

    @Inject
    Logger logger;

    public static final String DEFAULT_SCHEDULER_TIME_FOR_PKI_CDPS = "*,*,*,*,3,0,0";
    public static final String PKI_CDPS_SCHEDULER_TIMER_INFO = "pkiCDPSSchedulerTimerInfo";

    /**
     * This method will automatically trigger the job at the specified time intervals to get the CRL's from pki-manager to publish or unpublish .
     * 
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {
        logger.info("timeout method invoked in CRLDistributionPointServiceTimerServiceBean class");
        try {
            if (pkiraMembershipListener.isMaster()) {
                sendCRLNotificationRequestMessage();
            }
        } catch (TimerException e) {
            logger.error("Could not schedule  CRLDistributionPointServiceTimerService job {}", e.getMessage());
            logger.debug("Could not schedule  CRLDistributionPointServiceTimerService job ", e);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.CRLDistributionPointServiceTimerService", "PUBLISH_OR_UNPUBLISH_OF_CRLS_TO_CDPS",
                    "Could not schedule  CRLDistributionPointServiceTimerService job " + e.getMessage());

        }
        logger.info("End of timeout method in CRLDistributionPointServiceTimerServiceBean class");
    }

    /**
     * This Method is used to configure the timer for the given scheduler time.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.info("ScheduleJob method invoked in CRLDistributionPointServiceTimerServiceBean class");
        try {
            TimerUtility.createTimer(timerService, DEFAULT_SCHEDULER_TIME_FOR_PKI_CDPS, PKI_CDPS_SCHEDULER_TIMER_INFO);
        } catch (TimerException e) {
            logger.error("Could not schedule CRLDistributionPointServiceTimerService job {}", e.getMessage());
            logger.debug("Could not schedule CRLDistributionPointServiceTimerService job ", e);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.CRLDistributionPointServiceTimerService", "PUBLISH_OR_UNPUBLISH_OF_CRLS_TO_CDPS",
                    "Could not schedule CRLDistributionPointServiceTimerService job " + e.getMessage());
        }
        logger.info("End of scheduleJob method in CRLDistributionPointServiceTimerServiceBean class");
    }

    /**
     * This method is used to cancel the timer service if it is already registered timer service name
     */
    @PreDestroy
    public void cancelJob() {
        cancelTimerService();
    }

    private void sendCRLNotificationRequestMessage() {
        try {
            logger.info("GetAll  CRL'S to publish and unpublish");
            final CRLNotificationRequestMessage crlNotificationMessage = new CRLNotificationRequestMessage();
            crlNotificationRequestMessage.send(crlNotificationMessage);
            logger.info("End of notification method getCrlNotificationForPublishAndUnpublish");
        } catch (Exception exception) {
            logger.error("Sending notification message to get all CRL's for publishing and unpublishing to CDPS in CRLDistributionPointServiceTimerService due to {}", exception.getMessage());
            logger.debug("Sending notification message to get all CRL's for publishing and unpublishing to CDPS in CRLDistributionPointServiceTimerService due to {}", exception);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.CRLDistributionPointServiceTimerService", "PUBLISH_OR_UNPUBLISH_OF_CRLS_TO_CDPS",
                    "Failed to send notification message to get all CRL's for publishing and unpublishing to CDPS in CRLDistributionPointServiceTimerService: " + exception.getMessage());
            logger.debug("Exception stacktrace: ", exception);
        }
    }

    /**
     * This method is used to cancel the timer service if it is already registered timer service name
     */
    public void cancelTimerService() {
        try {
            TimerUtility.cancelTimerByTimerConfig(timerService, PKI_CDPS_SCHEDULER_TIMER_INFO);
            logger.info(PKI_CDPS_SCHEDULER_TIMER_INFO, " canceled");
        } catch (TimerException timerException) {
            logger.error(ErrorMessages.FAILED_TO_RECREATE_TIMER, timerException.getMessage());
            logger.debug(ErrorMessages.FAILED_TO_RECREATE_TIMER, timerException);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.CRLDistributionPointServiceTimerService", "PUBLISH_OR_UNPUBLISH_OF_CRLS_TO_CDPS",
                    ErrorMessages.FAILED_TO_RECREATE_TIMER + timerException.getMessage());

        }
    }

}
