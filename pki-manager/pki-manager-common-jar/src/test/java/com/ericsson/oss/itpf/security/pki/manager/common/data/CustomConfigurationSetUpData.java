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
package com.ericsson.oss.itpf.security.pki.manager.common.data;

import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CustomConfigurationData;

public class CustomConfigurationSetUpData {

    private static final int ID = 3;
    private static final String NAME = "CVN";
    private static final String VALUE = "1";
    private static final String NOTE = "16.9 - Change for test";
    private static final String OWNER = "credm";

    private CustomConfiguration customConfiguration;
    private CustomConfigurationData customConfigurationData;

    /**
     *
     */
    public CustomConfigurationSetUpData() {
        fillCustomConfiguration();
        fillCustomConfigurationData();
    }

    public CustomConfiguration createCustomConfiguration(final long id, final String name, final String value, final String note, final String owner) {
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

    public CustomConfigurationData createCustomConfigurationData(final String name, final String value, final String note, final String owner) {
        customConfigurationData = new CustomConfigurationData();
        customConfigurationData.setId(1);
        customConfigurationData.setName(name);
        customConfigurationData.setValue(value);
        customConfiguration.setNote(note);
        customConfiguration.setOwner(owner);
        return customConfigurationData;
    }

    private void fillCustomConfiguration() {
        customConfiguration = new CustomConfiguration();
        customConfiguration.setId(ID);
        customConfiguration.setName(NAME);
        customConfiguration.setValue(VALUE);
        customConfiguration.setNote(NOTE);
        customConfiguration.setOwner(OWNER);
    }

    private void fillCustomConfigurationData() {
        customConfigurationData = new CustomConfigurationData();
        customConfigurationData.setId(ID);
        customConfigurationData.setName(NAME);
        customConfigurationData.setValue(VALUE);
        customConfigurationData.setNote(NOTE);
        customConfigurationData.setOwner(OWNER);
    }

    /**
     * @return the customConfiguration
     */
    public CustomConfiguration getCustomConfiguration() {
        return customConfiguration;
    }

    /**
     * @return the customConfigurationData
     */
    public CustomConfigurationData getCustomConfigurationData() {
        return customConfigurationData;
    }

}
