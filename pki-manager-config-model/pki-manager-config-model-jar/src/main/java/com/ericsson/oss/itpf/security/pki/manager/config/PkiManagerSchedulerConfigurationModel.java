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
package com.ericsson.oss.itpf.security.pki.manager.config;

import com.ericsson.oss.itpf.modeling.annotation.DefaultValue;
import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.configparam.*;

/**
 * This class contains configuration parameter for all the scheduler jobs. The value of these configuration parameters can be updated using PIB.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = "pki-manager", description = "Configuration for statusUpdateSchedulerTime, fetchLatestCRLsSchedulerTime,caCertExpiryNotifySchedulerTime, entityCertExpiryNotifySchedulerTime,pkiManagerCredentialsManagementSchedulerTime,externalCACRLsSchedulerTime")
@ConfParamDefinitions
public class PkiManagerSchedulerConfigurationModel {
    @ConfParamDefinition(description = "Scheduled time to trigger status update scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,0,0,0")
    public String statusUpdateSchedulerTime;

    @ConfParamDefinition(description = "Scheduled time to trigger getLatestCRL scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,1,0,0")
    public String fetchLatestCRLsSchedulerTime;

    @ConfParamDefinition(description = "Scheduled time to trigger Pki manager ca certificate expiry notification scheduler", scope = Scope.GLOBAL)
    @DefaultValue("*,*,*,*,2,0,0")
    public String caCertExpiryNotifySchedulerTime;

    @ConfParamDefinition(description = "Scheduled time to trigger Pki manager entity certificate expiry notification scheduler", scope = Scope.GLOBAL)
    @DefaultValue("*,*,*,*,2,30,0")
    public String entityCertExpiryNotifySchedulerTime;

    @ConfParamDefinition(description = "Scheduled time to trigger Pki manager credentials management scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,1,30,0")
    public String pkiManagerCredentialsManagementSchedulerTime;

    @ConfParamDefinition(description = "Scheduled time to trigger getExternalCACRL scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,3,0,0")
    public String externalCACRLsSchedulerTime;
}
