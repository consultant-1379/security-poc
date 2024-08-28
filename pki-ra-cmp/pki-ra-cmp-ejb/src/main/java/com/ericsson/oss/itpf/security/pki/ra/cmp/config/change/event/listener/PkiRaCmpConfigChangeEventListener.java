/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.config.change.event.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.scheduler.DBMaintenanceTimerServiceBean;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.timer.constants.TimerServiceConstants;

/**
 * This class will listen the configuration change notification and will re create the EJB timer service w.r.to the changed scheduler time
 * 
 * @author tcsnapa
 * 
 */
@ApplicationScoped
public class PkiRaCmpConfigChangeEventListener {

    @Inject
    private Logger logger;

    @Inject
    private ConfigurationParamsListener configurationParamsListener;

    @Inject
    private DBMaintenanceTimerServiceBean dbMaintenanceTimerServiceBean;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * This method is used to listen any changes occurred in configuration environment and update the default values with the new values for the
     * changed properties.
     * 
     * @param dbMaintenanceSchedulerInterval
     *            This parameter is used to listen the dbMaintenanceSchedulerInterval from the pki-ra-cmp-model. Whenever the value changes, it has to
     *            be listened by this parameter and will be set to dbMaintenanceSchedulerInterval of ConfigurationParamsListener.
     */
    public void listenForDbMaintenanceSchedulerInterval(
            @Observes @ConfigurationChangeNotification(propertyName = "dbMaintenanceSchedulerInterval") final String dbMaintenanceSchedulerInterval) {
        logger.info("listenForDbMaintenanceSchedulerInterval is invoked");

        final String oldDbMaintenanceSchedulerInterval = configurationParamsListener.getDbMaintenanceSchedulerInterval();
        configureDbMaintenanceSchedulerInterval(oldDbMaintenanceSchedulerInterval, dbMaintenanceSchedulerInterval);
    }

    private void configureDbMaintenanceSchedulerInterval(final String oldDbMaintenanceSchedulerInterval,
            final String newDbMaintenanceSchedulerInterval) {
        try {
            dbMaintenanceTimerServiceBean.resetIntervalTimer(newDbMaintenanceSchedulerInterval);
            final String msg = String.format(TimerServiceConstants.DB_MAINTENANCE_SCHEDULER_CONFIG_PARAMETER_CHANGE_SUCCESS_MSG,
                    oldDbMaintenanceSchedulerInterval, newDbMaintenanceSchedulerInterval);
            systemRecorder.recordEvent("PKiRACMP.CONFIGURATION_CHANGE", EventLevel.COARSE, "PkiRaCmpConfigChangeEventListener",
                    "dbMaintenanceSchedulerInterval", msg);
        } catch (Exception exception) {
            logger.error(TimerServiceConstants.DB_MAINTENANCE_SCHEDULER_CONFIG_PARAMETER_CHANGE_FAILURE_MSG, newDbMaintenanceSchedulerInterval,
                    exception);
            final String msg = String.format(TimerServiceConstants.DB_MAINTENANCE_SCHEDULER_CONFIG_PARAMETER_CHANGE_FAILURE_MSG,
                    oldDbMaintenanceSchedulerInterval, exception.getMessage());
            systemRecorder.recordError("PKiRACMP.CONFIGURATION_CHANGE", ErrorSeverity.ERROR, "PkiRaCmpConfigChangeEventListener",
                    "dbMaintenanceSchedulerInterval", msg);
        }
    }
}
