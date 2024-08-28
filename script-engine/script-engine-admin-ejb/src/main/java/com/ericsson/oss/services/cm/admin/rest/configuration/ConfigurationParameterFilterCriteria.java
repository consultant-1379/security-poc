/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.rest.configuration;

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;

public class ConfigurationParameterFilterCriteria {

    private final ConfigurationParameter configurationParameter;

    public ConfigurationParameterFilterCriteria(ConfigurationParameter configurationParameter) {
        this.configurationParameter = configurationParameter;
    }

    public ConfigurationParameter getConfigurationParameter() {
        return configurationParameter;
    }
}
