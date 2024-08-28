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
package com.ericsson.oss.services.cm.admin.utility;

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationParameterFilterCriteria;
import com.ericsson.oss.services.cm.admin.validation.ValidationResult;
import org.apache.commons.cli.CommandLine;

public class ConfigurationServiceHelper {

    public static final String JVM_IDENTIFIER_PIB_API_KEYWORD = "jvmIdentifier";
    public static final String SERVICE_IDENTIFIER_PIB_API_KEYWORD = "serviceIdentifier";
    public static final String JVM_IDENTIFIER_CLI_KEYWORD = "app_server_identifier";
    public static final String SERVICE_IDENTIFIER_CLI_KEYWORD = "service_identifier";
    public static final String NAME_CLI_KEYWORD = "name";
    public static final String VALUE_CLI_KEYWORD = "value";
    public static final String PARAM_NAME_PIB_API_KEYWORD = "paramName";
    public static final String PARAM_VALUE_PIB_API_KEYWORD = "paramValue";

    public ConfigurationParameterFilterCriteria prepareFilterOptionsFromCliParameters(final CommandLine commandLine) {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        if (commandLine != null) {
            configurationParameter.setServiceIdentifier(commandLine.getOptionValue(SERVICE_IDENTIFIER_CLI_KEYWORD));
            configurationParameter.setJvmIdentifier(commandLine.getOptionValue(JVM_IDENTIFIER_CLI_KEYWORD));
            configurationParameter.setName(commandLine.getOptionValue(NAME_CLI_KEYWORD));
        }
        return new ConfigurationParameterFilterCriteria(configurationParameter);
    }

    public String getFullUrlForPibApi(ConfigurationParameterFilterCriteria configurationParameterFilterCriteria, String baseUrl) {
        ConfigurationParameter configurationParameter = configurationParameterFilterCriteria.getConfigurationParameter();
        String jvmIdentifier = configurationParameter.getJvmIdentifier();
        String serviceIdentifier = configurationParameter.getServiceIdentifier();
        if (serviceIdentifier == null && jvmIdentifier == null) {
            return baseUrl;
        } else if (jvmIdentifier == null) {
            return new StringBuilder(baseUrl)
                    .append("?").append(SERVICE_IDENTIFIER_PIB_API_KEYWORD).append("=").append(serviceIdentifier).toString();
        } else if (serviceIdentifier == null) {
            return new StringBuilder(baseUrl)
                    .append("?").append(JVM_IDENTIFIER_PIB_API_KEYWORD).append("=").append(jvmIdentifier).toString();
        } else {
            return new StringBuilder(baseUrl)
                    .append("?").append(SERVICE_IDENTIFIER_PIB_API_KEYWORD).append("=").append(serviceIdentifier)
                    .append("&").append(JVM_IDENTIFIER_PIB_API_KEYWORD).append("=").append(jvmIdentifier).toString();
        }
    }

    public ConfigurationParameter prepareConfigurationParameterFromCliParameters(final CommandLine commandLine,
                                                                                 final ValidationResult validationResult) {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        if (commandLine != null) {
            configurationParameter.setServiceIdentifier(commandLine.getOptionValue(SERVICE_IDENTIFIER_CLI_KEYWORD));
            configurationParameter.setJvmIdentifier(commandLine.getOptionValue(JVM_IDENTIFIER_CLI_KEYWORD));
            configurationParameter.setName(commandLine.getOptionValue(NAME_CLI_KEYWORD));
            configurationParameter.setValue(validationResult.getValue());
        }
        return configurationParameter;
    }
}
