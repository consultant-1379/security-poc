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

package com.ericsson.oss.itpf.security.pki.core.service.scheduling;

import java.util.List;
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
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.TimerUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.service.cluster.MembershipListenerInterface;
import com.ericsson.oss.itpf.security.pki.core.service.config.PKICoreConfigurationParams;

/**
 * This class fetches the corresponding CRLSchedulerTime value from PKICoreConfigurationListener and triggers the scheduler at the corresponding time interval which in turn triggers the generateCRL
 * method at the particular time interval
 * 
 * @author xnagsow
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class CRLGenerationTimerServiceBean {

    public static final String CRL_GENERATION_TIMER_INFO = "CRLGenerationTimerInfo";
    public static final String FAILED_TO_START_CRL_SCHEDULER_JOB = "CRL(s) will not be generated automatically as per the scheduled time";
    public static final String FAILED_TO_READ_CONFIGURATION_PARAMETER_VALUE = "Configuration Property Not found with name generateCRLsSchedulerTime. Could not schedule PKICore CRL Generation Timer job due to {}";

    @Inject
    private PKICoreConfigurationParams pkiCoreConfigurationParams;

    @Inject
    private TimerService timerService;

    @Inject
    MembershipListenerInterface membershipListener;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Inject
    private CRLGenerationBean crlGenerationBean;

    private final AtomicBoolean isCRLSchedulerJobBusy = new AtomicBoolean(false);

    /**
     * This method will automatically trigger the job Generate CRL with respect to the time configured by the scheduler.
     * 
     * @param timer
     *            Timer configured by the scheduleJob method
     */
    @Timeout
    public void timeout(final Timer timer) {
        logger.debug("timeout method invoked in CRLGenerationTimerServiceBean class");

        if (!isCRLSchedulerJobBusy.compareAndSet(false, true)) {
            logger.debug("Previous timer {} is already running and waiting for next time out", CRL_GENERATION_TIMER_INFO);
            return;
        }

        try {
            if (membershipListener.isMaster()) {
                generateAllCRLs();
            }
        } catch (Exception exception) {
            logger.error(ErrorMessages.AUTOMATIC_CRL_GENERATION_JOB_FAILED + exception.getMessage());
            logger.debug("Automatic CRL generation job failed:", exception);
            systemRecorder.recordSecurityEvent("PkiCoreCRLManagementService", "CRLGenerationTimerService", "Exception occured while automatic generation of CRL", "CRLGenetation",
                    ErrorSeverity.CRITICAL, "FAILURE");
        } finally {
            isCRLSchedulerJobBusy.set(false);
        }

        logger.debug("End of timeout method in CRLGenerationTimerServiceBean class");
    }

    /**
     * This method is used to configure the timer to trigger the scheduler job.
     */
    @PostConstruct
    public void scheduleJob() {
        logger.debug("ScheduleJob method invoked in CRLGenerationTimerServiceBean class");

        try {
            final String generateCRLSchedulerTime = pkiCoreConfigurationParams.getGenerateCRLsSchedulerTime();
            createTimer(generateCRLSchedulerTime);
        } catch (ConfigurationPropertyNotFoundException configurationPropertyNotFoundException) {
            logger.debug("Configuration Property Not found with name generateCRLsSchedulerTime. Could not schedule PKICore CRL Generation Timer job:", configurationPropertyNotFoundException);
            logger.error(FAILED_TO_READ_CONFIGURATION_PARAMETER_VALUE, configurationPropertyNotFoundException.getMessage());
            systemRecorder.recordError("PKISERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKI.CRLGenerationTimerService", "AUTOMATICALLY_CRL_GENERATION", FAILED_TO_START_CRL_SCHEDULER_JOB);
        } catch (Exception exception) {
            logger.error("Could not schedule PKICore CRL Generation Timer job: {}", exception.getMessage());
            logger.debug("Could not schedule PKICore CRL Generation Timer job:", exception);
            systemRecorder.recordError("PKISERVICE.TIMERSERVICE_FAILED", ErrorSeverity.CRITICAL, "PKI.CRLGenerationTimerService", "AUTOMATICALLY_CRL_GENERATION", FAILED_TO_START_CRL_SCHEDULER_JOB);
        }

        logger.debug("End of ScheduleJob method invoked in CRLGenerationTimerServiceBean class");
    }

    public void resetIntervalTimer(final String newGenerateCRLSchedulerTime) throws IllegalArgumentException, TimerException {
        logger.debug("Resetting interval timer for class {}. Setting interval to {}", this.getClass().getSimpleName(), newGenerateCRLSchedulerTime);

        TimerUtility.cancelTimerByTimerConfig(timerService, CRL_GENERATION_TIMER_INFO);
        createTimer(newGenerateCRLSchedulerTime);
    }

    private void createTimer(final String schedulerTime) throws IllegalArgumentException, TimerException {
        if (schedulerTime == null) {
            logger.error(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name generateCRLSchedulerTime. Could not schedule PKICore CRL Generation Timer job");
            throw new IllegalArgumentException(ErrorMessages.CONFIGURATION_PROPERTY_VALUE_NULL + " with name generateCRLSchedulerTime.");
        }

        TimerUtility.createTimer(timerService, schedulerTime, CRL_GENERATION_TIMER_INFO);
    }

    private void generateAllCRLs() {
        final List<CertificateAuthority> certificateAuthorityList = caEntityPersistenceHandler.getAllCAsByStatus(CAStatus.ACTIVE, CAStatus.INACTIVE);
        if (!certificateAuthorityList.isEmpty()) {
            for (CertificateAuthority certificateAuthority : certificateAuthorityList) {
                if (certificateAuthority.getActiveCertificate() != null) {
                    crlGenerationBean.generateCRL(certificateAuthority.getName(), certificateAuthority.getActiveCertificate());
                }
                for (Certificate certificate : certificateAuthority.getInActiveCertificates()) {
                    if (certificate != null && certificate.getStatus().equals(CertificateStatus.INACTIVE)) {
                        crlGenerationBean.generateCRL(certificateAuthority.getName(), certificate);
                    }
                }
            }
        }
    }

}