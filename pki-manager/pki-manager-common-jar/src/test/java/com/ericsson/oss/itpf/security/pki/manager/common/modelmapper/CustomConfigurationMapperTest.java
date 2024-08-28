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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.data.CustomConfigurationSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.EntityCategoryPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CustomConfigurationData;

@RunWith(MockitoJUnitRunner.class)
public class CustomConfigurationMapperTest {

    @InjectMocks
    CustomConfigurationMapper customConfigurationMapper;

    CustomConfigurationSetUpData customConfigurationSetUpData;

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityCategoryPersistenceHandler.class);

    static CustomConfiguration customConfiguration;
    static CustomConfiguration customConfigurationWithNameAndOwner;
    static CustomConfiguration customConfigurationWithId;
    static CustomConfigurationData customConfigurationData;

    @Before
    public void prepareCustomConfigurationObject() {

        customConfigurationSetUpData = new CustomConfigurationSetUpData();
        customConfiguration = customConfigurationSetUpData.createCustomConfiguration(0, "name", "value", "note", "owner");

        customConfigurationWithNameAndOwner = customConfigurationSetUpData.createCustomConfiguration(0, "name", null, null, "owner");

        customConfigurationWithId = customConfigurationSetUpData.createCustomConfiguration(1, null, null, null, null);

        customConfigurationData = customConfigurationSetUpData.createCustomConfigurationData("name", "value", "note", "owner");
    }

    @Test
    public void testFromAPIToModel() {
        final CustomConfigurationData customConfigurationDataReturned = customConfigurationMapper.fromAPIToModel(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationDataReturned.getName());
        assertEquals(customConfiguration.getValue(), customConfigurationDataReturned.getValue());
        assertEquals(customConfiguration.getNote(), customConfigurationDataReturned.getNote());
        assertEquals(customConfiguration.getOwner(), customConfigurationDataReturned.getOwner());
        assertEquals(customConfiguration.getId(), customConfigurationDataReturned.getId());
    }

    @Test
    public void testToAPiFromModel() {
        final CustomConfiguration customConfigurationReturned = customConfigurationMapper.toAPIFromModel(customConfigurationData);
        assertEquals(customConfigurationData.getName(), customConfigurationReturned.getName());
        assertEquals(customConfigurationData.getValue(), customConfigurationReturned.getValue());
        assertEquals(customConfigurationData.getNote(), customConfigurationReturned.getNote());
        assertEquals(customConfigurationData.getOwner(), customConfigurationReturned.getOwner());
        assertEquals(customConfigurationData.getId(), customConfigurationReturned.getId());
    }

}
