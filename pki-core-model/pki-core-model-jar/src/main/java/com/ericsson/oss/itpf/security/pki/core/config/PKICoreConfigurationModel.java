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
package com.ericsson.oss.itpf.security.pki.core.config;

import com.ericsson.oss.itpf.modeling.annotation.DefaultValue;
import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.configparam.*;

/**
 * PKICoreConfigurationModel class contains the configuration parameter generateCRLsSchedulerTime.This parameter will provide the scheduler time to pki-core to trigger generateCRL job.The value of
 * generateCRLsSchedulerTime can be updated using PIB.
 *
 * @author xnagsow
 **/
@EModel(namespace = "pki-core", description = "Configuration for generateCRLsSchedulerTime")
@ConfParamDefinitions
public class PKICoreConfigurationModel {
    @ConfParamDefinition(description = "Interval time to invoke generateCRL scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,0,30,0")
    public String generateCRLsSchedulerTime;
}
