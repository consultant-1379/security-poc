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

import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

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
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.TDPSUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class fetches the StatusUpdateTime value from PKIManagerConfigurationListener and triggers the scheduler at the corresponding time interval which in turn trigger the jobs - Certificate status
 * update and CRL status update at the particular time interval
 * 
 * @author xnagsow
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class PKIManagerStatusUpdateTimerServiceBean {

    @EServiceRef
    CertificateManagementService coreCertificateManagementService;

    @EServiceRef
    EntityManagementService entityManagementService;

    @EServiceRef
    CRLManagementService coreCRLManagementService;

    @Inject
    private EntitiesManager entitiesManager;

    @Inject
    private TimerService timerService;

    @Inject
    private PKIManagerConfigurationListener configurationListener;

    @Inject
    private CRLManager crlManager;

    @Inject
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    private CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    private EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Inject
    private TDPSUnpublishNotifier tdpsUnpublishNotifier;

    @Inject
    private Logger logger;

    @Inject
    MembershipListenerInterface membershipListener;

    @Inject
    SystemRecorder systemRecorder;

    private final AtomicBoolean isCRLSchedulerJobBusy = new AtomicBoolean(false);

    /**
     * This method will automatically trigger the jobs update certificate status, unpublish expired certificates from TDPS and update crl status in both pki-manager and pki-core with respect to the
     * time configured by the scheduler.
     * 
     * @param timer
     */
    @Timeout
    public void timeout(final Timer timer) {
        logger.debug("timeout method invoked in PKIManagerStatusUpdateTimerServiceBean class.");

        if (!isCRLSchedulerJobBusy.compareAndSet(false, true)) {
            logger.info("Previous timer {} is already running and waiting for next time out", TimerServiceConstants.PKI_MANAGER_STATUS_UPDATE_TIMER_INFO);
            systemRecorder.recordError("PKISERVICE.TIMERSERVICE_FAILED", ErrorSeverity.WARNING, "PKI.PKIManagerStatusUpdateTimerServiceBean", "Update status of certificates and CRLs",
                    "Previous timer " + TimerServiceConstants.PKI_MANAGER_STATUS_UPDATE_TIMER_INFO + " is already running and waiting for next time out.");
            return;
        }

        try {
            if (membershipListener.isMaster()) {
                crlManager.deleteDuplicatesAndInsertLatestCRLs();
                coreCertificateManagementService.updateCertificateStatusToExpired();
                certificatePersistenceHelper.updateCertificateStatusToExpired();
                unpublishExpiredCertificates();
                coreCRLManagementService.updateCRLStatusToExpired();
                crlManager.updateCRLStatusToExpired();
                coreCRLManagementService.updateCRLStatusToInvalid();
                crlManager.unpublishInvalidCRLs();
                entitiesManager.updateEntityStatusToInactive();
            }
        } catch (final Exception exception) {
            logger.debug("Error occured while updating the job status ", exception);
            logger.error(ErrorMessages.AUTOMATIC_STATUS_UPDATE_JOB_FAILED + exception.getMessage());
            systemRecorder.recordSecurityEvent("Certificates and CRLs Timer Service", "PKIManagerStatusUpdateTimerServiceBean",
                    "Could not update status of certificates and CRLs as scheduler job has been failed.", "PKIManagerStatusUpdateTimerServiceBean.timeout", ErrorSeverity.CRITICAL, "FAILURE");
        } finally {
            isCRLSchedulerJobBusy.set(false);
        }

        logger.debug("End of timeout method in PKIManagerStatusUpdateTimerServiceBean class.");

    }

    /**
     * This method is automatically triggered during application initialization. This will create the schedule for the timer with the parameters configured in model.
     * 
     */
    @PostConstruct
    public void scheduleJob() {
        logger.debug("ScheduleJob method in PKIManagerStatusUpdateTimerServiceBean class.");

        try {
            final String statusUpdateSchedulerTime = configurationListener.getStatusUpdateSchedulerTime();
            if (statusUpdateSchedulerTime != null) {
                createTimer(statusUpdateSchedulerTime);
            } else {
                logger.error(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name statusUpdateSchedulerTime. Could not schedule PkiManagerStatusUpdateTimerInfo job.");
                systemRecorder.recordSecurityEvent("Certificates and CRLs Timer Service", "PKIManagerStatusUpdateTimerServiceBean", "Could not schedule PKIManagerStatusUpdateTimerInfo job.",
                        "PKIManagerStatusUpdateTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
            }

        } catch (final ConfigurationPropertyNotFoundException configurationPropertyNotFoundException) {
            logger.debug("Error occured while fetching configuration property with name statusUpdateSchedulerTime ", configurationPropertyNotFoundException);
            logger.error(TimerServiceConstants.FAILED_TO_READ_STATUS_UPDATE_CONFIGURATION_PARAMETER_VALUE, configurationPropertyNotFoundException.getMessage());
            systemRecorder.recordSecurityEvent("Certificates and CRLs Timer Service", "PKIManagerStatusUpdateTimerServiceBean", "Could not schedule PKIManagerStatusUpdateTimerInfo job.",
                    "PKIManagerStatusUpdateTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (final Exception exception) {
            logger.debug("Error occured while scheduling PKIManager StatusUpdate Timer job ", exception);
            logger.error(TimerServiceConstants.FAILED_TO_START_GET_STATUS_UPDATE_SCHEDULER_JOB, exception.getMessage());
            systemRecorder.recordSecurityEvent("Certificates and CRLs Timer Service", "PKIManagerStatusUpdateTimerServiceBean", "Could not schedule PKIManagerStatusUpdateTimerInfo job.",
                    "PKIManagerStatusUpdateTimerServiceBean.scheduleJob", ErrorSeverity.CRITICAL, "FAILURE");
        }

        logger.debug("End of ScheduleJob method invoked in PKIManagerStatusUpdateTimerServiceBean class.");
    }

    /**
     * This method is used to reset the timer configuration with newly changed configuration parameter value
     * 
     * @param newStatusUpdateSchedulerTime
     *            is the parameter of newly changed configuration parameter value
     * @throws TimerException
     *             is thrown when failed to create or cancel an EJB timer.
     */
    public void resetIntervalTimer(final String newStatusUpdateSchedulerTime) throws TimerException {
        logger.debug("Resetting interval timer for class {}. Setting interval to {}", this.getClass().getSimpleName(), newStatusUpdateSchedulerTime);

        TimerUtility.cancelTimerByTimerConfig(timerService, TimerServiceConstants.PKI_MANAGER_STATUS_UPDATE_TIMER_INFO);
        // TODO (TORF-164889)Configuration parameter validations will do in the next phase.
        createTimer(newStatusUpdateSchedulerTime);

        logger.debug("End of resetIntervalTimer method invoked in PKIManagerStatusUpdateTimerServiceBean class");
    }

    private void createTimer(final String schedulerTime) throws TimerException {
        TimerUtility.createTimer(timerService, schedulerTime, TimerServiceConstants.PKI_MANAGER_STATUS_UPDATE_TIMER_INFO);
    }

    private void unpublishExpiredCertificates() throws CertificateServiceException {
        logger.debug("unpublishExpiredCertificates method in PKIManagerStatusUpdateTimerServiceBean class started.");
        final Map<String, List<Certificate>> caCertificates = caCertificatePersistenceHelper.getExpiredCACertificatesToUnpublish();
        for (Map.Entry<String, List<Certificate>> entry : caCertificates.entrySet()) {
            final String caName = entry.getKey();
            try {
                tdpsUnpublishNotifier.notify(EntityType.CA_ENTITY, caName, caCertificates.get(caName));
            } catch (CertificateEncodingException certificateEncodingException) {
                logger.error("Error while unpublishing certificates for the CA {} - {}", caName, certificateEncodingException.getMessage());
                logger.debug("Error while unpublishing certificates for the CA {} - {}", caName, certificateEncodingException);
                systemRecorder.recordError("PKISERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKI.PKIManagerStatusUpdateTimerService", "UNPUBLISH_INVALID_CA_CERTS_FROM_TDPS",
                        "Error while unpublishing certificates for the CA " + caName + " - " + certificateEncodingException.getMessage());
            }
        }

        final Map<String, List<Certificate>> entityCertificates = entityCertificatePersistenceHelper.getExpiredEntityCertificatesToUnpublish();
        for (Map.Entry<String, List<Certificate>> entry : entityCertificates.entrySet()) {
            final String entityName = entry.getKey();
            try {
                tdpsUnpublishNotifier.notify(EntityType.ENTITY, entityName, entityCertificates.get(entityName));
            } catch (CertificateEncodingException certificateEncodingException) {
                logger.error("Error while unpublishing certificates for the entity {} - {}", entityName, certificateEncodingException.getMessage());
                logger.debug("Error while unpublishing certificates for the entity {} - {}", entityName, certificateEncodingException);
                systemRecorder.recordError("PKISERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKI.PKIManagerStatusUpdateTimerService", "UNPUBLISH_INVALID_ENTITY_CERTS_FROM_TDPS",
                        "Error while unpublishing certificates for the entity " + entityName + " - " + certificateEncodingException.getMessage());
            }
        }
        logger.debug("unpublishExpiredCertificates method in PKIManagerStatusUpdateTimerServiceBean class End. ");
    }
}
