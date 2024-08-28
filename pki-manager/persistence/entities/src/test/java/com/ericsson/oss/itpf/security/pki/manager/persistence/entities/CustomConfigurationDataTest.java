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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class CustomConfigurationDataTest {

    CustomConfigurationData customConfigurationData;
    CustomConfigurationData expectedCustomConfigurationData;

    @Before
    public void setup() {

        customConfigurationData = getCustomConfigurationData();
        expectedCustomConfigurationData = getCustomConfigurationData();
    }

    @Test
    public void testEntityCategoryForEquals() {

        customConfigurationData.hashCode();
        customConfigurationData.toString();
        customConfigurationData.getId();
        customConfigurationData.getName();
        customConfigurationData.getOwner();
        customConfigurationData.getNote();
        customConfigurationData.getValue();
        customConfigurationData.getModifiedDate();

        assertTrue(customConfigurationData.equals(customConfigurationData));
        assertTrue(customConfigurationData.equals(expectedCustomConfigurationData));

        customConfigurationData.equals(null);
        customConfigurationData.equals(new String());
        customConfigurationData.setId(2);
        customConfigurationData.equals(expectedCustomConfigurationData);
        customConfigurationData.setId(1);
        customConfigurationData.setName("test");

        assertFalse(customConfigurationData.equals(expectedCustomConfigurationData));

        customConfigurationData.setName(null);

        assertFalse(customConfigurationData.equals(expectedCustomConfigurationData));

    }

    private CustomConfigurationData getCustomConfigurationData() {
        CustomConfigurationData customConfigurationData = new CustomConfigurationData();
        customConfigurationData.setId(1);
        customConfigurationData.setOwner("TestOwner");
        customConfigurationData.setNote("TestNote");
        customConfigurationData.setName("param1");
        customConfigurationData.setValue("value1");
        return customConfigurationData;
    }


}
