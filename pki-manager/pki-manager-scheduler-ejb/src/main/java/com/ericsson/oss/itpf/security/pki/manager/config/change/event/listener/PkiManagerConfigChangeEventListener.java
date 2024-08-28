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
package com.ericsson.oss.itpf.security.pki.manager.config.change.event.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.service.schedular.*;
import com.ericsson.oss.itpf.security.pki.manager.service.timer.constants.TimerServiceConstants;

/**
 * This class will listen the configuration change notification and will re create the EJB timer service w.r.to the changed scheduler time
 * 
 * @author tcsnapa
 * 
 */
@ApplicationScoped
public class PkiManagerConfigChangeEventListener {

    @Inject
    private Logger logger;

    @Inject
    private PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Inject
    private PKIManagerStatusUpdateTimerServiceBean pKIManagerStatusUpdateTimerServiceBean;

    @Inject
    private GetLatestCRLTimerServiceBean getLatestCRLTimerServiceBean;

    @Inject
    private PkiCredentialsManagementTimerServiceBean pkiCredentialsManagementTimerServiceBean;

    @Inject
    private CACertExpiryNotificationTimerServiceBean caCertExpiryNotificationTimerServiceBean;

    @Inject
    private EntityCertExpiryNotificationTimerServiceBean entityCertExpiryNotificationTimerServiceBean;

    @Inject
    ExternalCACRLTimerServiceBean externalCACRLTimerServiceBean;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * This method is used to listen any changes occurred in configuration environment and update the default values with the new values for the changed properties.
     * 
     * @param statusUpdateSchedulerTime
     *            This parameter is used to listen the statusUpdateSchedulerrTime from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and will be set
     *            to statusUpdateSchedulerTime of PkiManagerConfigurationListener.
     */
    public void listenForStatusUpdateTimeChange(@Observes @ConfigurationChangeNotification(propertyName = "statusUpdateSchedulerTime") final String statusUpdateSchedulerTime) {
        logger.info("listenForStatusUpdateTimeChange is invoked");

        final String oldStatusUpdateSchedulerTimeValue = pkiManagerConfigurationListener.getStatusUpdateSchedulerTime();
        configureStatusUpdateSchedularTime(oldStatusUpdateSchedulerTimeValue, statusUpdateSchedulerTime);
    }

    private void configureStatusUpdateSchedularTime(final String oldStatusUpdateSchedulerTimeValue, final String newStatusUpdateSchedulerTimeValue) {
        try {
            pKIManagerStatusUpdateTimerServiceBean.resetIntervalTimer(newStatusUpdateSchedulerTimeValue);
            recordEvent(TimerServiceConstants.STATUS_UPDATE_SCHEDULER_TIME_CONFIG_PARAMETER, TimerServiceConstants.STATUS_UPDATE_CONFIG_PARAMETER_CHANGE_SUCCESS_MSG,
                    oldStatusUpdateSchedulerTimeValue, newStatusUpdateSchedulerTimeValue);
            // TODO (TORF-164889)Configuration parameter validations will do in the next phase.
        } catch (Exception exception) {
            logger.error(TimerServiceConstants.STATUS_UPDATE_ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, newStatusUpdateSchedulerTimeValue, exception.getMessage());
            logger.debug(TimerServiceConstants.STATUS_UPDATE_ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, exception);
            recordError(TimerServiceConstants.STATUS_UPDATE_SCHEDULER_TIME_CONFIG_PARAMETER, ErrorSeverity.ERROR,
                    TimerServiceConstants.STATUS_UPDATE_ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, newStatusUpdateSchedulerTimeValue, exception.getMessage());
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property fetchLatestCRLsSchedulerTime and update the default value with the new value for the changed
     * property.
     * 
     * @param fetchLatestCRLsSchedulerTime
     *            This parameter is used to listen the fetchLatestCRLsSchedulerTime from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and will be
     *            set to fetchLatestCRLsSchedulerTime of PkiManagerConfigurationListener.
     */

    public void listenForFetchLatestCRLsSchedulerTimeChange(@Observes @ConfigurationChangeNotification(propertyName = "fetchLatestCRLsSchedulerTime") final String fetchLatestCRLsSchedulerTime) {
        logger.info("listenForAnyFetchLatestCRLsSchedulerTimeChange is invoked");
        final String oldFetchLatestCRLsSchedulerTimeValue = pkiManagerConfigurationListener.getFetchLatestCRLsSchedulerTime();
        configurefetchLatestCRLsSchedulerTimeParameter(oldFetchLatestCRLsSchedulerTimeValue, fetchLatestCRLsSchedulerTime);
    }

    private void configurefetchLatestCRLsSchedulerTimeParameter(final String oldFetchLatestCRLsSchedulerTimeValue, final String newFetchLatestCRLsSchedulerTimeValue) {
        try {
            getLatestCRLTimerServiceBean.resetIntervalTimer(newFetchLatestCRLsSchedulerTimeValue);
            recordEvent(TimerServiceConstants.FETCH_LATEST_CRLS_SCHEDULER_TIME_CONFIG_PARAMETER, TimerServiceConstants.CONFIG_PARAMETER_CHANGE_SUCCESS_MSG, oldFetchLatestCRLsSchedulerTimeValue,
                    newFetchLatestCRLsSchedulerTimeValue);
            // TODO (TORF-164889)Configuration parameter validations will do in the next phase.
        } catch (Exception exception) {
            logger.error(TimerServiceConstants.ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, newFetchLatestCRLsSchedulerTimeValue, exception.getMessage());
            logger.debug(TimerServiceConstants.ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, newFetchLatestCRLsSchedulerTimeValue, exception);
            recordError(TimerServiceConstants.FETCH_LATEST_CRLS_SCHEDULER_TIME_CONFIG_PARAMETER, ErrorSeverity.ERROR, TimerServiceConstants.ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG,
                    newFetchLatestCRLsSchedulerTimeValue, exception.getMessage());
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property pkiManagerCredentialsManagementSchedulerTime and update the default value with the new value for
     * the changed property.
     * 
     * @param pkiManagerCredentialsManagementSchedulerTime
     *            This parameter is used to listen the pkiManagerCredentialsManagementSchedulerTime from the pki-manager-config-model. Whenever the value changes, it has to be listened by this
     *            parameter and will be set to pkiManagerCredentialsManagementSchedulerTime of PkiManagerConfigurationListener.
     */

    public void listenForPkiManagerCredentialsManagementSchedulerTimeChange(
            @Observes @ConfigurationChangeNotification(propertyName = "pkiManagerCredentialsManagementSchedulerTime") final String pkiManagerCredentialsManagementSchedulerTime) {

        logger.info("listenForAnyPkiManagerCredentialsManagementSchedulerTimeChange invoked");

        if (pkiManagerCredentialsManagementSchedulerTime != null) {
            logger.debug(
                    "Configuration change listener invoked since the pkiManagerCredentialsManagementSchedulerTime value has got changed in the model. The new pkiManagerCredentialsManagementSchedulerTime is {}",
                    pkiManagerCredentialsManagementSchedulerTime);
            pkiManagerConfigurationListener.setPkiManagerCredentialsManagementSchedulerTime(pkiManagerCredentialsManagementSchedulerTime);
            pkiCredentialsManagementTimerServiceBean.scheduleJob();
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property caCertExpiryNotifySchedulerTime and update the default value with the new value for the changed
     * property.
     * 
     * @param caCertExpiryNotifySchedulerTime
     *            This parameter is used to listen the caCertExpiryNotifySchedulerTime from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and will
     *            be set to caCertExpiryNotifySchedulerTime of PkiManagerConfigurationListener.
     */

    public void listenForCaCertExpiryNotifySchedulerTimeChange(@Observes @ConfigurationChangeNotification(propertyName = "caCertExpiryNotifySchedulerTime") final String caCertExpiryNotifySchedulerTime) {

        logger.info("listenForCaCertExpiryNotifySchedulerTimeChange invoked");

        if (caCertExpiryNotifySchedulerTime != null) {
            logger.debug("Configuration change listener invoked since the caCertExpiryNotifySchedulerTime value has got changed in the model. The new caCertExpiryNotifySchedulerTime is {}",
                    caCertExpiryNotifySchedulerTime);
            pkiManagerConfigurationListener.setCaCertExpiryNotifySchedulerTime(caCertExpiryNotifySchedulerTime);
            caCertExpiryNotificationTimerServiceBean.setTimer();
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property entityCertExpiryNotifySchedulerTime and update the default value with the new value for the
     * changed property.
     * 
     * @param entityCertExpiryNotifySchedulerTime
     *            This parameter is used to listen the entityCertExpiryNotifySchedulerTime from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and
     *            will be set to entityCertExpiryNotifySchedulerTime of PkiManagerConfigurationListener.
     */

    public void listenForEntityCertExpiryNotifySchedulerTimeChange(
            @Observes @ConfigurationChangeNotification(propertyName = "entityCertExpiryNotifySchedulerTime") final String entityCertExpiryNotifySchedulerTime) {

        logger.info("listenForEntityCertExpiryNotifySchedulerTimeChange invoked");

        if (entityCertExpiryNotifySchedulerTime != null) {
            logger.debug("Configuration change listener invoked since the entityCertExpiryNotifySchedulerTime value has got changed in the model. The new entityCertExpiryNotifySchedulerTime is {}",
                    entityCertExpiryNotifySchedulerTime);
            pkiManagerConfigurationListener.setEntityCertExpiryNotifySchedulerTime(entityCertExpiryNotifySchedulerTime);
            entityCertExpiryNotificationTimerServiceBean.setTimer();
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property externalCACRLsSchedulerTime and update the default value with the new value for the changed
     * property.
     * 
     * @param externalCACRLsSchedulerTime
     *            This parameter is used to listen the externalCACRLsSchedulerTime from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and will be
     *            set to externalCACRLsSchedulerTime of PkiManagerConfigurationListener.
     */

    public void listenForExternalCACRLSchedulerTimeChange(@Observes @ConfigurationChangeNotification(propertyName = "externalCACRLsSchedulerTime") final String externalCACRLsSchedulerTime) {

        logger.info("listenForExternalCACRLSchedulerTimeChange invoked");

        if (externalCACRLsSchedulerTime != null && externalCACRLsSchedulerTime.matches(TimerServiceConstants.TIME_PATTERN_TO_UPDATE_SCHEDULAR)) {
            logger.debug("Configuration change listener invoked since the externalCACRLsSchedulerTime value has got changed in the model. The new externalCACRLsSchedulerTime is {}",
                    externalCACRLsSchedulerTime);
            pkiManagerConfigurationListener.setExternalCACRLsSchedulerTime(externalCACRLsSchedulerTime);
            externalCACRLTimerServiceBean.scheduleJob();
        }
    }

    private void recordEvent(final String configParameterName, final String additionalInformation, final Object... args) {
        systemRecorder.recordEvent("PKIMANAGER.CONFIGURATION_CHANGE", EventLevel.COARSE, "PkiManagerConfigChangeEventListener", configParameterName, String.format(additionalInformation, args));
    }

    private void recordError(final String configParameterName, final ErrorSeverity errorSeverity, final String additionalInformation, final Object... args) {
        systemRecorder.recordError("PKIMANAGER.CONFIGURATION_CHANGE", errorSeverity, "PkiManagerConfigChangeEventListener", configParameterName, String.format(additionalInformation, args));
    }

}
