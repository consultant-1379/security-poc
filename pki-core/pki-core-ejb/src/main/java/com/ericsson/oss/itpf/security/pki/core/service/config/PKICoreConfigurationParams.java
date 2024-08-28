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

package com.ericsson.oss.itpf.security.pki.core.service.config;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.validation.constraints.NotNull;

import com.ericsson.oss.itpf.sdk.config.annotation.Configured;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;

/**
 * ConfigurationListener class fetches the configuration parameters from the model using the property name. Configuration parameters for CRL service includes the properties of
 * generateCRLsSchedulerTime
 * 
 * @author xnagsow
 */
@ApplicationScoped
@Profiled
public class PKICoreConfigurationParams {

    @Inject
    @NotNull
    @Configured(propertyName = "generateCRLsSchedulerTime")
    private String generateCRLsSchedulerTime;

    /**
     * @return configuration parameter - generateCRLsSchedulerTime
     */

    public String getGenerateCRLsSchedulerTime() {
        return this.generateCRLsSchedulerTime;
    }

    /**
     * @param generateCRLsSchedulerTime
     *            the generateCRLsSchedulerTime to set
     */
    public void setGenerateCRLsSchedulerTime(final String generateCRLsSchedulerTime) {
        this.generateCRLsSchedulerTime = generateCRLsSchedulerTime;
    }

}