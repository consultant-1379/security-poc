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
package com.ericsson.oss.itpf.security.pki.core.service.config.listener;

import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;
import com.ericsson.oss.itpf.security.pki.core.service.config.PKICoreConfigurationParams;
import com.ericsson.oss.itpf.security.pki.core.service.scheduling.CRLGenerationTimerServiceBean;

/**
 * This class will listen the configuration change notification and will re create the EJB timer service w.r.to the changed scheduler time
 * 
 * @author tcsnapa
 * 
 */
public class PkiCoreConfigChangeEventListener {

    public static final String CRL_SCHEDULER_TIME_CONFIG_PARAMETER = "generateCRLsSchedulerTime";
    public static final String CONFIG_PARAMETER_CHANGE_SUCCESS_MSG = "generateCRLsSchedulerTime configuration parameter value changed, from old value = '%s' to new value = '%s' successfully";
    public static final String CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Failed to change the generateCRLsSchedulerTime configuration parameter value= '%s' due to %s";
    public static final String CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG = "generateCRLsSchedulerTime parameter value changed, from old value = '%s' to new value = '%s'. But, new job is not scheduled with new value of generateCRLsSchedulerTime";
    public static final String ERROR_CONFIG_PARAMETER_IS_NULL_OR_SAME_VALUE_MSG = "generateCRLsSchedulerTime parameter was not changed. Either the new value is the same or the new value was malformed and the change was ignored. Old Value is {} and new Value is {}";
    public static final String ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG = "generateCRLsSchedulerTime parameter value changed from old value: {} to new Value: {}. But, new job is not scheduled with new value of generateCRLsSchedulerTime due to {} ";
    public static final String ERROR_CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Unable to reset CRLGenerationTimerInfo Job with new scheduler Time: {} due to {} ";

    @Inject
    private CRLGenerationTimerServiceBean cRLGenerationTimerServiceBean;

    @Inject
    private PKICoreConfigurationParams pkiCoreConfigurationParams;

    @Inject
    private Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * This method will listen any changes occurred in configuration environment for the property generateCRLSchedulerTime and update the default value with the new value for the changed property
     * 
     * @param generateCRLSchedulerTime
     *            This parameter is used to listen the generateCRLSchedulerTime from the pki-core-model. Whenever the value changes, it has to be listened by this parameter and will be set to
     *            generateCRLSchedulerTime of PkiCoreConfiguration.
     */
    public void listenForGenerateCRLSchedularTime(@Observes @ConfigurationChangeNotification(propertyName = "generateCRLsSchedulerTime") final String generateCRLSchedulerTime) {
        final String currentValue = pkiCoreConfigurationParams.getGenerateCRLsSchedulerTime();
        configureCRLSchedulerTimeParameter(currentValue, generateCRLSchedulerTime);
    }

    private void configureCRLSchedulerTimeParameter(final String oldValue, final String newValue) {
        try {
            validateCRLSchedulerTimeParameter(oldValue, newValue);

            pkiCoreConfigurationParams.setGenerateCRLsSchedulerTime(newValue);
            cRLGenerationTimerServiceBean.resetIntervalTimer(newValue);

            recordEvent(CONFIG_PARAMETER_CHANGE_SUCCESS_MSG, oldValue, newValue);
        } catch (TimerException timerException) {
            logger.error(ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, oldValue, newValue, timerException.getMessage());
            logger.debug("generateCRLsSchedulerTime parameter value changed from old value to new Value. But, new job is not scheduled with new value of generateCRLsSchedulerTime:", timerException);
            recordError(ErrorSeverity.ERROR, CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG, oldValue, newValue);
        } catch (Exception exception) {
            logger.error(ERROR_CONFIG_PARAMETER_CHANGE_FAILURE_MSG, newValue, exception.getMessage());
            logger.debug("Unable to reset CRLGenerationTimerInfo Job with new scheduler Time:", exception);
            recordError(ErrorSeverity.ERROR, CONFIG_PARAMETER_CHANGE_FAILURE_MSG, newValue, exception.getMessage());
        }
    }

    private void validateCRLSchedulerTimeParameter(final String oldValue, final String newValue) throws IllegalArgumentException {
        if (newValue == null || newValue.equals(oldValue)) {
            logger.error(ERROR_CONFIG_PARAMETER_IS_NULL_OR_SAME_VALUE_MSG, oldValue, newValue);
            throw new IllegalArgumentException("Either the new value is the same or the new value was malformed and the change was ignored.");
        }
    }

    private void recordEvent(final String additionalInformation, final Object... args) {
        systemRecorder.recordEvent("PKICORE.CONFIGURATION_CHANGE", EventLevel.COARSE, "PKICore", CRL_SCHEDULER_TIME_CONFIG_PARAMETER, String.format(additionalInformation, args));
    }

    private void recordError(final ErrorSeverity errorSeverity, final String additionalInformation, final Object... args) {
        systemRecorder.recordError("PKICORE.CONFIGURATION_CHANGE", errorSeverity, "PKICore", CRL_SCHEDULER_TIME_CONFIG_PARAMETER, String.format(additionalInformation, args));
    }
}