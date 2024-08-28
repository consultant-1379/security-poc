package com.ericsson.oss.services.cm.admin.utility;

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;
import com.ericsson.oss.services.cm.admin.rest.client.RestUrls;
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationParameterFilterCriteria;
import org.junit.Assert;
import org.junit.Test;


public class ConfigurationServiceHelperTest {

    private ConfigurationServiceHelper configurationServiceHelper = new ConfigurationServiceHelper();

    @Test
    public void constructPibApiGetAllParametersUrlTestForGlobalScopedParameters() {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter);
        String actual = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria,
                RestUrls.CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        Assert.assertEquals("http://cli-service:8080/pib/configurationService/getAllConfigParametersInScope", actual);
    }

    @Test
    public void constructPibApiGetAllParametersUrlTestForServiceScopedParameters() {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setServiceIdentifier("serviceIdentifierValue");
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter);
        String actual = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria,
                RestUrls.CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        Assert.assertEquals("http://cli-service:8080/pib/configurationService/getAllConfigParametersInScope?serviceIdentifier=serviceIdentifierValue", actual);
    }

    @Test
    public void constructPibApiGetAllParametersUrlTestForJvmScopedParameters() {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setJvmIdentifier("jvmIdentifierValue");
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter);
        String actual = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria,
                RestUrls.CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        Assert.assertEquals("http://cli-service:8080/pib/configurationService/getAllConfigParametersInScope?jvmIdentifier=jvmIdentifierValue", actual);
    }

    @Test
    public void constructPibApiGetAllParametersUrlTestForNullJvmScopedParameterAndNonNullServiceIdentifier() {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setJvmIdentifier(null);
        configurationParameter.setServiceIdentifier("serviceIdentifierValue");
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter);
        String actual = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria,
                RestUrls.CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        Assert.assertEquals("http://cli-service:8080/pib/configurationService/getAllConfigParametersInScope?serviceIdentifier=serviceIdentifierValue", actual);
    }

    @Test
    public void constructPibApiGetAllParametersUrlTestForNonNullJvmScopedParameterAndNullServiceIdentifier() {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setJvmIdentifier("jvmIdentifierValue");
        configurationParameter.setServiceIdentifier(null);
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter);
        String actual = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria,
                RestUrls.CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        Assert.assertEquals("http://cli-service:8080/pib/configurationService/getAllConfigParametersInScope?jvmIdentifier=jvmIdentifierValue", actual);
    }

    @Test
    public void constructPibApiGetAllParametersUrlTestForJvmAndServiceScopedParameters() {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setServiceIdentifier("serviceIdentifierValue");
        configurationParameter.setJvmIdentifier("jvmIdentifierValue");
        ConfigurationParameterFilterCriteria configurationParameterFilterCriteria =
                new ConfigurationParameterFilterCriteria(configurationParameter);
        String actual = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria,
                RestUrls.CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        Assert.assertEquals("http://cli-service:8080/pib/configurationService/getAllConfigParametersInScope?serviceIdentifier=serviceIdentifierValue&jvmIdentifier=jvmIdentifierValue", actual);
    }
}