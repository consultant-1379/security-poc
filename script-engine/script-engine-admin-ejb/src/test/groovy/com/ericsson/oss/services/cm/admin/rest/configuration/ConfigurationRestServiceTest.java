package com.ericsson.oss.services.cm.admin.rest.configuration;

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationRestServiceTest {

    @Mock
    private PasswordHelper passwordHelper;

    @InjectMocks
    private ConfigurationRestService configurationRestService = new ConfigurationRestService();

    @Test(expected = ConfigurationRestServiceException.class)
    public void getParameterTest() {
        Mockito.when(passwordHelper.decryptDecode(Mockito.anyString())).thenReturn("cGliVXNlcjozcmljNTUwTio");
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setName("AP_SNMP_AUDIT_TIME");
        ConfigurationParameterFilterCriteria filterCriteria = new ConfigurationParameterFilterCriteria(configurationParameter);
        configurationRestService.getParameter(filterCriteria);
    }

    @Test(expected = ConfigurationRestServiceException.class)
    public void updateParameterTest() {
        Mockito.when(passwordHelper.decryptDecode(Mockito.anyString())).thenReturn("cGliVXNlcjozcmljNTUwTio");
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setName("AP_SNMP_AUDIT_TIME");
        configurationParameter.setValue("02:45");
        configurationRestService.updateParameter(configurationParameter);
    }

}