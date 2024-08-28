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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.common.data;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;

public class CustomConfigurationSetUpData {

    CustomConfiguration customConfiguration;
    CustomConfigurations customConfigurations;
    CustomConfiguration customConfigurationWithId;
    //CustomConfigurationData customConfigurationData;

    public CustomConfiguration createCustomConfigurationSetupData(final long id, final String name, final String value, final String note, final String owner) {
        customConfiguration = new CustomConfiguration();
        if (id != 0)
            customConfiguration.setId(1);
        if (name != null)
            customConfiguration.setName(name);
        if (value != null)
            customConfiguration.setValue(value);
        if (note != null)
            customConfiguration.setNote(note);
        if (owner != null)
            customConfiguration.setOwner(owner);

        return customConfiguration;
    }

    public CustomConfiguration createCustomConfigurationSetupDataWithId() {
        customConfigurationWithId = new CustomConfiguration();
        customConfigurationWithId.setId(1);
        return customConfigurationWithId;
    }

    /**
     * @param customConfigurationList
     * @return CustomConfigurations
     */
    public CustomConfigurations createCustomConfigurationsSetupData(List<CustomConfiguration> customConfigurationList) {
        customConfigurations = new CustomConfigurations();
        customConfigurations.setCustomConfigurations(customConfigurationList);
        return customConfigurations;
    }

    //    public CustomConfigurationData createCustomConfigurationData(final String name, final String value, final String note, final String owner) {
    //        customConfigurationData = new CustomConfigurationData();
    //        customConfigurationData.setName(name);
    //        customConfigurationData.setValue(value);
    //        customConfigurationData.setNote(note);
    //        customConfigurationData.setOwner(owner);
    //        return customConfigurationData;
    //    }

}
