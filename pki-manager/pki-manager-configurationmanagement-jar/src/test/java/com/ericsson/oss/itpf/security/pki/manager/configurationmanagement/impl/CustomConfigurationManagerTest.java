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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.CustomConfigurationPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.common.data.CustomConfigurationSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;

@RunWith(MockitoJUnitRunner.class)
public class CustomConfigurationManagerTest {

    @InjectMocks
    CustomConfigurationManager customConfigurationManager;

    @Mock
    CustomConfigurationPersistenceHandler customConfigurationPersistenceHandler;

    static CustomConfigurationSetUpData customConfigurationSetUpData;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CustomConfigurationManagerTest.class);

    private static CustomConfiguration customConfiguration;

    private static CustomConfiguration customConfiguration1;
    private static CustomConfigurations customConfigurations;

    @BeforeClass
    public static void preCondition() {
        customConfigurationSetUpData = new CustomConfigurationSetUpData();

        customConfiguration = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "Owner");
        customConfiguration1 = customConfigurationSetUpData.createCustomConfigurationSetupData(1, "Name1", "Value1", "Note1", "Owner1");
        List<CustomConfiguration> customConfigurationList = new ArrayList<CustomConfiguration>();
        customConfigurationList.add(customConfiguration);
        customConfigurationList.add(customConfiguration1);
        
        customConfigurations = customConfigurationSetUpData.createCustomConfigurationsSetupData(customConfigurationList);
    }

    @Test
    public void testCreateCustomConfiguration() {
        logger.info("CustomConfiguration DATA IN CREATE TEST CASE ----- " + customConfiguration.getName() + " " + customConfiguration.getValue() + " " + customConfiguration.getNote() + " "
                + customConfiguration.getOwner());
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        Mockito.when(customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration)).thenReturn(false);
        final CustomConfiguration customConfigurationReturned = customConfigurationManager.createCustomConfiguration(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationReturned.getName());
        assertEquals(customConfiguration.getValue(), customConfigurationReturned.getValue());
        assertEquals(customConfiguration.getOwner(), customConfigurationReturned.getOwner());
        assertEquals(customConfiguration.getNote(), customConfigurationReturned.getNote());
    }

    @Test
    public void testCreateCustomConfigurations() {
        logger.info("CustomConfigurations DATA IN CREATE TEST CASE ----- ");
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration1)).thenReturn(customConfiguration1);
        Mockito.when(customConfigurationPersistenceHandler.isPresentCustomConfiguration(Mockito.any(CustomConfiguration.class))).thenReturn(false);
        customConfigurationManager.createCustomConfigurations(customConfigurations);
//        final CustomConfigurations customConfigurationsReturned = customConfigurationManager.createCustomConfigurations(customConfigurations);
        assertEquals(customConfigurations.getCustomConfigurations().size(), 2);
    }

    @Test
    public void testUpdateCustomConfiguration() {
        logger.info("CustomConfiguration DATA IN UPDATE TEST CASE ----- " + customConfiguration.getName() + " " + customConfiguration.getValue() + " " + customConfiguration.getNote() + " "
                + customConfiguration.getOwner());
        Mockito.when(customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        final CustomConfiguration customConfigurationReturned = customConfigurationManager.updateCustomConfiguration(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationReturned.getName());
        assertEquals(customConfiguration.getValue(), customConfigurationReturned.getValue());
        assertEquals(customConfiguration.getOwner(), customConfigurationReturned.getOwner());
        assertEquals(customConfiguration.getNote(), customConfigurationReturned.getNote());
    }

    @Test
    public void testUpdateCustomsConfiguration() {
        logger.info("CustomConfigurations DATA IN UPDATE TEST CASE ----- ");
        Mockito.when(customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        Mockito.when(customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration1)).thenReturn(customConfiguration1);
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration1)).thenReturn(customConfiguration1);
        Mockito.when(customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration)).thenReturn(true);
        Mockito.when(customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration1)).thenReturn(false);
        customConfigurationManager.updateCustomConfigurations(customConfigurations);
        assertEquals(customConfigurations.getCustomConfigurations().size(), 2);
    }

    @Test
    public void testGetCustomConfiguration() {
        logger.info("CustomConfiguration DATA IN GET TEST CASE ----- " + customConfiguration.getName() + " " + customConfiguration.getValue() + " " + customConfiguration.getNote() + " "
                + customConfiguration.getOwner());
        Mockito.when(customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        final CustomConfiguration customConfigurationReturned = customConfigurationManager.getCustomConfiguration(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationReturned.getName());
        assertEquals(customConfiguration.getOwner(), customConfigurationReturned.getOwner());
    }

    @Test
    public void testGetCustomsConfiguration() {
        logger.info("CustomConfigurations DATA IN GET TEST CASE ----- ");
        Mockito.when(customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        Mockito.when(customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration1)).thenReturn(customConfiguration1);
        customConfigurationManager.getCustomConfigurations(customConfigurations);
        assertEquals(customConfigurations.getCustomConfigurations().size(), 2);
    }

    @Test
    public void testDeleteCustomConfiguration() {
        logger.info("CustomConfiguration DATA IN DELETE TEST CASE ----- " + customConfiguration.getName() + " " + customConfiguration.getValue() + " " + customConfiguration.getNote() + " "
                + customConfiguration.getOwner());
        Mockito.doNothing().when(customConfigurationPersistenceHandler).deleteCustomConfiguration(customConfiguration);
        customConfigurationManager.deleteCustomConfiguration(customConfiguration);
    }

    @Test
    public void testDeleteCustomsConfiguration() {
        logger.info("CustomConfigurations DATA IN DELETE TEST CASE ----- ");
        Mockito.doNothing().when(customConfigurationPersistenceHandler).deleteCustomConfiguration(Mockito.any(CustomConfiguration.class));
        customConfigurationManager.deleteCustomConfigurations(customConfigurations);
    }


    @Test
    public void testIsPresentCustomConfiguration() {
        Mockito.when(customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration)).thenReturn(true);
        logger.info("CustomConfiguration DATA IN IS PRESENT TEST CASE ----- " + customConfiguration.getName() + " " + customConfiguration.getValue() + " " + customConfiguration.getNote() + " "
                + customConfiguration.getOwner());
        final Boolean isPresent = customConfigurationManager.isPresentCustomConfiguration(customConfiguration);
        assertTrue(isPresent);
    }

    @Test(expected=CustomConfigurationInvalidException.class)
    public void TestValidateNameNull() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, null, "Value", "Note", "Owner");
        customConfigurationManager.getCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected=CustomConfigurationInvalidException.class)
    public void TestValidateNameEmpty() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "", "Value", "Note", "Owner");
        customConfigurationManager.getCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestValidateOwnerNull() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", null);
        customConfigurationManager.getCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestValidateOwnerEmpty() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "");
        customConfigurationManager.getCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestFailValidationUpdate() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "");
        customConfigurationManager.updateCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestFailValidationCreate() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "");
        customConfigurationManager.createCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestFailValidationDelete() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "");
        customConfigurationManager.deleteCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestFailValidationIsPresent() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "");
        customConfigurationManager.isPresentCustomConfiguration(customConfigurationInvalid);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void TestFailValidationCreateMultiple() {
        final CustomConfiguration customConfigurationInvalid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "");
        final CustomConfiguration customConfigurationValid = customConfigurationSetUpData.createCustomConfigurationSetupData(0, "Name", "Value", "Note", "Owner");
        List<CustomConfiguration> customConfigurationList = new ArrayList<CustomConfiguration>();
        customConfigurationList.add(customConfigurationValid);
        customConfigurationList.add(customConfigurationInvalid);
        CustomConfigurations customConfigurationsInvalid = customConfigurationSetUpData.createCustomConfigurationsSetupData(customConfigurationList);
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfigurationInvalid)).thenReturn(customConfigurationInvalid);
        Mockito.when(customConfigurationPersistenceHandler.createCustomConfiguration(customConfigurationValid)).thenReturn(customConfigurationValid);
        customConfigurationManager.createCustomConfigurations(customConfigurationsInvalid);
    }

    @Test
    public void TestOnCreateWithNull() {
        CustomConfigurations customConfigurationsInvalid = customConfigurationSetUpData.createCustomConfigurationsSetupData(null);
        CustomConfigurations customConfigurationsCreated = customConfigurationManager.createCustomConfigurations(customConfigurationsInvalid);
        assertEquals(0, customConfigurationsCreated.getCustomConfigurations().size());
    }

    @Test
    public void TestOnCreateWithEmptyList() {
        CustomConfigurations customConfigurationsEmpty = customConfigurationSetUpData.createCustomConfigurationsSetupData(new ArrayList<CustomConfiguration>());
        CustomConfigurations customConfigurationsCreated = customConfigurationManager.createCustomConfigurations(customConfigurationsEmpty);
        assertEquals(0, customConfigurationsCreated.getCustomConfigurations().size());
    }

    @Test
    public void TestOnUpdateWithNull() {
        CustomConfigurations customConfigurationsInvalid = customConfigurationSetUpData.createCustomConfigurationsSetupData(null);
        CustomConfigurations customConfigurationsUpdated = customConfigurationManager.updateCustomConfigurations(customConfigurationsInvalid);
        assertEquals(0, customConfigurationsUpdated.getCustomConfigurations().size());
    }

    @Test
    public void TestOnUpdateWithEmptyList() {
        CustomConfigurations customConfigurationsEmpty = customConfigurationSetUpData.createCustomConfigurationsSetupData(new ArrayList<CustomConfiguration>());
        CustomConfigurations customConfigurationsUpdated = customConfigurationManager.updateCustomConfigurations(customConfigurationsEmpty);
        assertEquals(0, customConfigurationsUpdated.getCustomConfigurations().size());
    }

    @Test
    public void TestOnGetWithNull() {
        CustomConfigurations customConfigurationsInvalid = customConfigurationSetUpData.createCustomConfigurationsSetupData(null);
        CustomConfigurations customConfigurationsRetrieved = customConfigurationManager.getCustomConfigurations(customConfigurationsInvalid);
        assertEquals(0, customConfigurationsRetrieved.getCustomConfigurations().size());
    }

    @Test
    public void TestOnGetWithEmptyList() {
        CustomConfigurations customConfigurationsEmpty = customConfigurationSetUpData.createCustomConfigurationsSetupData(new ArrayList<CustomConfiguration>());
        CustomConfigurations customConfigurationsRetrieved = customConfigurationManager.getCustomConfigurations(customConfigurationsEmpty);
        assertEquals(0, customConfigurationsRetrieved.getCustomConfigurations().size());
    }

    @Test
    public void TestOnDeleteWithNull() {
        CustomConfigurations customConfigurationsInvalid = customConfigurationSetUpData.createCustomConfigurationsSetupData(null);
        customConfigurationManager.deleteCustomConfigurations(customConfigurationsInvalid);
    }

    @Test
    public void TestOnDeleteWithEmptyList() {
        CustomConfigurations customConfigurationsEmpty = customConfigurationSetUpData.createCustomConfigurationsSetupData(new ArrayList<CustomConfiguration>());
        customConfigurationManager.deleteCustomConfigurations(customConfigurationsEmpty);
    }

}
