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
package com.ericsson.oss.itpf.security.pki.manager.service.timer.constants;

/**
 * This class will holds the constants which are related to pki-manager scheduler service.
 * 
 * @author tcsnapa
 *
 */
public class TimerServiceConstants {

    public static final String DEFAULT_SCHEDULER_TIME_FOR_PKI_MANAGER_CREDM = "*,*,*,*,*,*/1,0";
    public static final String PKI_MANAGER_CREDENTIALS_MGMT_SCHEDULER_TIMER_INFO = "PKIManagerCredentialsMgmtTimerInfo";
    public static final String GET_LATEST_CRL_TIMER_INFO = "GetLatestCRLTimerInfo";
    public static final String PKI_MANAGER_STATUS_UPDATE_TIMER_INFO = "PkiManagerStatusUpdateTimerInfo";
    public static final String CERT_EXPIRY_NOTIFICATION_SCHEDULER_INFO = "certExpiryNotificationScheduler";
    public static final String EXTERNAL_CA_CRL_TIMER_INFO = "externalCACRLTimerInfo";
    public static final String TIME_PATTERN_TO_UPDATE_SCHEDULAR = "[*][,][*][,][*][,][*][,]([0-1]?[0-9]|2?[0-3])[,][0-5]?[0-9][,][0-5]?[0-9]";

    public static final String FETCH_LATEST_CRLS_SCHEDULER_TIME_CONFIG_PARAMETER = "fetchLatestCRLsSchedulerTime";
    public static final String CONFIG_PARAMETER_CHANGE_SUCCESS_MSG = "fetchLatestCRLsSchedulerTime configuration parameter value is changed successfully from old value = '%s' to new value = '%s'";
    public static final String CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Failed to change the fetchLatestCRLsSchedulerTime configuration parameter value= '%s' due to %s";
    public static final String ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG = "fetchLatestCRLsSchedulerTime parameter value is changed successfully from old value: {} to new Value: {}. But, new job is not scheduled with new value of fetchLatestCRLsSchedulerTime due to {} ";
    public static final String ERROR_CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Unable to reset GetLatestCRLTimerInfo Job with new scheduler Time: {} due to {} ";
    public static final String ERROR_CONFIG_PARAMETER_IS_NULL = "The new value was malformed";

    public static final String STATUS_UPDATE_SCHEDULER_TIME_CONFIG_PARAMETER = "statusUpdateSchedulerTime";
    public static final String STATUS_UPDATE_CONFIG_PARAMETER_CHANGE_SUCCESS_MSG = "statusUpdateSchedulerTime configuration parameter value is changed successfully from old value = '%s' to new value = '%s'";
    public static final String STATUS_UPDATE_CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Failed to change the statusUpdateSchedulerTime configuration parameter value= '%s' due to %s";
    public static final String STATUS_UPDATE_ERROR_CONFIG_PARAMETER_CHANGE_SCHEDULE_JOB_FAIL_MSG = "statusUpdateSchedulerTime parameter value is changed successfully from old value: {} to new Value: {}. But, new job is not scheduled with new value of statusUpdateSchedulerTime due to {} ";
    public static final String STATUS_UPDATE_ERROR_CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Unable to reset PkiManagerStatusUpdateTimerInfo Job with new scheduler Time: {} due to {} ";

    public static final String FAILED_TO_START_GETLATESTCRL_SCHEDULER_JOB = "Could not schedule PKIManager GetLatestCRLTimerInfo Timer job due to {}";
    public static final String FAILED_TO_READ_CONFIGURATION_PARAMETER_VALUE = "Configuration Property Not found with name fetchLatestCRLsSchedulerTime. Could not schedule PKIManager GetLatestCRLTimerInfo Timer job due to {}";

    public static final String FAILED_TO_START_GET_STATUS_UPDATE_SCHEDULER_JOB = "Could not schedule  PKIManager StatusUpdate Timer job due to {}";
    public static final String FAILED_TO_READ_STATUS_UPDATE_CONFIGURATION_PARAMETER_VALUE = "Configuration Property Not found with name statusUpdateSchedulerTime. Could not schedule PkiManagerStatusUpdateTimerInfo job due to {}";

    public static final String DEFAULT_SCHEDULER_TIME_FOR_SUPPORTED_ALGORITHMS_CACHE = "*,*,*,*,*,*,*/30";
    public static final String FAILED_TO_LOAD_SUPPORTED_ALGORITHMS_CACHE = "Failed to load supported algorithms cache. Hence SCEP and CMP enrollments will fail";
    public static final String FAILED_TO_CANCEL_TIMER = "Failed to cancel the timer SupportedAlgorithmsCacheLoaderTimerServiceInfo";
    public static final String FAILED_TO_START_SUPPORTED_ALGORITHMS_CACHE_LOADER_SCHEDULER_JOB = "Failed to create a schedule job to load supported algorithms cache";
    public static final String SUPPORTED_ALGORITHMS_CACHE_LOADER_TIMER_SERVICE_INFO = "SupportedAlgorithmsCacheLoaderTimerServiceInfo";

}
