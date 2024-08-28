/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.ra.cmp.service.timer.constants;

/**
 * This class will holds the constants which are related to pki-ra-cmp scheduler
 * service.
 *
 * @author tcsnapa
 */
public class TimerServiceConstants {

    private TimerServiceConstants() {
    }

    public static final String DEFAULT_SCHEDULER_TIME_FOR_CMP_CRL_CACHE_LOADER_SCHEDULER = "*,*,*,*,*,*,*/30";
    public static final String FAILED_TO_INTIALIZE_CMP_CRL_CACHE = "Failed to initialize Cmp crl cache hence Cmp enrollment will fail";
    public static final String FAILED_TO_CANCEL_TIMER = "Failed to cancel the timer CmpCrlCacheLoaderTimerServiceInfo";
    public static final String FAILED_TO_START_CMP_CRL_CACHE_LOADER_SCHEDULER_JOB = "Failed to create a schedule job to load Cmp Crl cache";
    public static final String FAILED_TO_START_HOUSE_KEEPING_SCHEDULER_JOB = "DB House Keeping Activities for PKIRACmp will not be done automatically";
    public static final String CMP_CRL_CACHE_LOADER_TIMER_SERVICE_INFO = "CmpCrlCacheLoaderTimerServiceInfo";
    public static final String DB_MAINTENANCE_TIMER_SERVICE_INFO = "DBMaintenanceTimerServiceInfo";
    public static final String DB_MAINTENANCE_SCHEDULER_CONFIG_PARAMETER_CHANGE_SUCCESS_MSG = "dbMaintenanceSchedulerInterval configuration parameter value is changed successfully from old value = '%s' to new value = '%s'";
    public static final String DB_MAINTENANCE_SCHEDULER_CONFIG_PARAMETER_CHANGE_FAILURE_MSG = "Failed to change the statusUpdateSchedulerTime configuration parameter value= '%s' due to %s";
}