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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ConfigurationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl.CustomConfigurationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;

@RunWith(MockitoJUnitRunner.class)
public class CustomConfigurationManagementServiceBeanTest {

    @InjectMocks
    CustomConfigurationManagementServiceBean customConfigurationService;

    @Mock
    ConfigurationManagementAuthorizationManager configurationManagementAuthorizationManager;

    @Mock
    CustomConfigurationManager customConfigurationManager;

    @Mock
    Logger logger;

    @Test
    public void testGetCustomConfiguration() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.READ);
        final CustomConfiguration customConfigurationToReturn = new CustomConfiguration();
        customConfigurationToReturn.setId(7);
        customConfigurationToReturn.setName("CVN");
        customConfigurationToReturn.setOwner("credM");
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.getCustomConfiguration(customConfiguration)).thenReturn(customConfigurationToReturn);
        final CustomConfiguration customConfigurationReturned = customConfigurationService.getCustomConfiguration(customConfiguration);
        assertEquals(7, customConfigurationReturned.getId());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationNotFoundException.class)
    public void testGetCustomConfigurationNotFound() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.READ);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.getCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationNotFoundException.class);
        customConfigurationService.getCustomConfiguration(customConfiguration);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationInvalidException.class)
    public void testGetCustomConfigurationInvalid() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.READ);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.getCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationInvalidException.class);
        customConfigurationService.getCustomConfiguration(customConfiguration);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationServiceException.class)
    public void testGetCustomConfigurationServiceException() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.READ);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.getCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationServiceException.class);
        customConfigurationService.getCustomConfiguration(customConfiguration);
    }

    @Test
    public void testUpdateCustomConfiguration() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.UPDATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.updateCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        final CustomConfiguration customConfigurationReturned = customConfigurationService.updateCustomConfiguration(customConfiguration);
        assertEquals(9, customConfigurationReturned.getId());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationNotFoundException.class)
    public void testUpdateCustomConfigurationNotFound() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.UPDATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.updateCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationNotFoundException.class);
        customConfigurationService.updateCustomConfiguration(customConfiguration);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationInvalidException.class)
    public void testUpdateCustomConfigurationInvalid() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.UPDATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.updateCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationInvalidException.class);
        customConfigurationService.updateCustomConfiguration(customConfiguration);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationServiceException.class)
    public void testUpdateCustomConfigurationServiceException() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.UPDATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.updateCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationServiceException.class);
        customConfigurationService.updateCustomConfiguration(customConfiguration);
    }

    @Test
    public void testCreateCustomConfiguration() throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.CREATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.createCustomConfiguration(customConfiguration)).thenReturn(customConfiguration);
        final CustomConfiguration customConfigurationReturned = customConfigurationService.createCustomConfiguration(customConfiguration);
        assertEquals(9, customConfigurationReturned.getId());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationInvalidException.class)
    public void testCreateCustomConfigurationInvalid() throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.CREATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.createCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationInvalidException.class);
        customConfigurationService.createCustomConfiguration(customConfiguration);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CustomConfigurationServiceException.class)
    public void testCreateCustomConfigurationServiceException() throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.CREATE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.when(customConfigurationManager.createCustomConfiguration(customConfiguration)).thenThrow(CustomConfigurationServiceException.class);
        customConfigurationService.createCustomConfiguration(customConfiguration);
    }

    @Test
    public void testDeleteCustomConfiguration() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.DELETE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.doNothing().when(customConfigurationManager).deleteCustomConfiguration(customConfiguration);
        customConfigurationService.deleteCustomConfiguration(customConfiguration);
    }

    @Test(expected = CustomConfigurationNotFoundException.class)
    public void testDeleteCustomConfigurationNotFound() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.DELETE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.doThrow(CustomConfigurationNotFoundException.class).when(customConfigurationManager).deleteCustomConfiguration(customConfiguration);
        customConfigurationService.deleteCustomConfiguration(customConfiguration);
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void testDeleteCustomConfigurationInvalid() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.DELETE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.doThrow(CustomConfigurationInvalidException.class).when(customConfigurationManager).deleteCustomConfiguration(customConfiguration);
        customConfigurationService.deleteCustomConfiguration(customConfiguration);
    }

    @Test(expected = CustomConfigurationServiceException.class)
    public void testDeleteCustomConfigurationSeviceException() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.DELETE);
        final CustomConfiguration customConfiguration = new CustomConfiguration();
        customConfiguration.setId(9);
        customConfiguration.setName("CVN");
        customConfiguration.setOwner("credM");
        Mockito.doThrow(CustomConfigurationServiceException.class).when(customConfigurationManager).deleteCustomConfiguration(customConfiguration);
        customConfigurationService.deleteCustomConfiguration(customConfiguration);
    }

    @Test
    public void testGetCustomConfigurations() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.READ);
        final CustomConfiguration customConfiguration1 = new CustomConfiguration();
        customConfiguration1.setId(7);
        customConfiguration1.setName("CVN");
        customConfiguration1.setOwner("credM");
        final CustomConfiguration customConfiguration2 = new CustomConfiguration();
        customConfiguration2.setId(8);
        customConfiguration2.setOwner("credM");
        customConfiguration2.setName("IVN");
        List <CustomConfiguration> customConfigurationList = new ArrayList<CustomConfiguration>();
        customConfigurationList.add(customConfiguration1);
        customConfigurationList.add(customConfiguration2);
        final CustomConfigurations customConfigurations = new CustomConfigurations();
        customConfigurations.setCustomConfigurations(customConfigurationList);
        Mockito.when(customConfigurationManager.getCustomConfigurations(customConfigurations)).thenReturn(customConfigurations);
        final CustomConfigurations customConfigurationsReturned = customConfigurationService.getCustomConfigurations(customConfigurations);
        assertEquals(7, customConfigurationsReturned.getCustomConfigurations().get(0).getId());
    }
    
    @Test
    public void testUpdateCustomConfigurations() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.UPDATE);
        final CustomConfiguration customConfiguration1 = new CustomConfiguration();
        customConfiguration1.setName("CVN");
        customConfiguration1.setOwner("credM");
        final CustomConfiguration customConfiguration2 = new CustomConfiguration();
        customConfiguration2.setName("IVN");
        customConfiguration2.setOwner("credM");
        List <CustomConfiguration> customConfigurationList = new ArrayList<CustomConfiguration>();
        customConfigurationList.add(customConfiguration1);
        customConfigurationList.add(customConfiguration2);
        
        final CustomConfiguration customConfiguration1Out = new CustomConfiguration();
        customConfiguration1Out.setId(7);
        customConfiguration1Out.setName("CVN");
        customConfiguration1Out.setOwner("credM");
        final CustomConfiguration customConfiguration2Out = new CustomConfiguration();
        customConfiguration2Out.setId(8);
        customConfiguration2Out.setName("IVN");
        customConfiguration2Out.setOwner("credM");
        List <CustomConfiguration> customConfigurationList2 = new ArrayList<CustomConfiguration>();
        customConfigurationList2.add(customConfiguration1Out);
        customConfigurationList2.add(customConfiguration2Out);
        
        
        final CustomConfigurations customConfigurations = new CustomConfigurations();
        customConfigurations.setCustomConfigurations(customConfigurationList);
        final CustomConfigurations customConfigurationsOut = new CustomConfigurations();
        customConfigurationsOut.setCustomConfigurations(customConfigurationList2);
        
        Mockito.when(customConfigurationManager.updateCustomConfigurations(customConfigurations)).thenReturn(customConfigurationsOut);
        final CustomConfigurations customConfigurationsReturned = customConfigurationService.updateCustomConfigurations(customConfigurations);
        assertEquals(customConfigurationsOut.getCustomConfigurations().get(1).getId(), customConfigurationsReturned.getCustomConfigurations().get(1).getId());
    }
    
    @Test
    public void testisPresentCustomConfigurations() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.DELETE);
       
        final CustomConfiguration customConfiguration1 = new CustomConfiguration();
        customConfiguration1.setName("CVN");
        customConfiguration1.setOwner("credM");
        
        Mockito.when(customConfigurationManager.isPresentCustomConfiguration(customConfiguration1)).thenReturn(true);
        assertTrue(customConfigurationService.isPresentCustomConfiguration(customConfiguration1));
    }

    @Test
    public void testDeleteCustomConfigurations() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.DELETE);
        final CustomConfigurations customConfigurations = new CustomConfigurations();
        
        final CustomConfiguration customConfiguration1 = new CustomConfiguration();
        customConfiguration1.setName("CVN");
        customConfiguration1.setOwner("credM");
        final CustomConfiguration customConfiguration2 = new CustomConfiguration();
        customConfiguration2.setName("IVN");
        customConfiguration2.setOwner("credM");
        List <CustomConfiguration> customConfigurationList = new ArrayList<CustomConfiguration>();
        customConfigurationList.add(customConfiguration1);
        customConfigurationList.add(customConfiguration2);
        customConfigurations.setCustomConfigurations(customConfigurationList);
        
        Mockito.doNothing().when(customConfigurationManager).deleteCustomConfigurations(customConfigurations);
        customConfigurationService.deleteCustomConfigurations(customConfigurations);
    }

    @Test
    public void testCreateCustomConfigurations() throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeCustomConfigurationOperations(ActionType.CREATE);
 
        
        final CustomConfiguration customConfiguration1 = new CustomConfiguration();
        customConfiguration1.setName("CVN");
        customConfiguration1.setOwner("credM");
        final CustomConfiguration customConfiguration2 = new CustomConfiguration();
        customConfiguration2.setName("IVN");
        customConfiguration2.setOwner("credM");
        List <CustomConfiguration> customConfigurationList = new ArrayList<CustomConfiguration>();
        customConfigurationList.add(customConfiguration1);
        customConfigurationList.add(customConfiguration2);
        
        final CustomConfiguration customConfiguration1Out = new CustomConfiguration();
        customConfiguration1Out.setName("CVN");
        customConfiguration1Out.setOwner("credM");
        final CustomConfiguration customConfiguration2Out = new CustomConfiguration();
        customConfiguration2Out.setName("IVN");
        customConfiguration2Out.setOwner("credM");
        List <CustomConfiguration> customConfigurationListOut = new ArrayList<CustomConfiguration>();
        customConfigurationListOut.add(customConfiguration1Out);
        customConfigurationListOut.add(customConfiguration2Out);
        
        final CustomConfigurations customConfigurations = new CustomConfigurations();
        customConfigurations.setCustomConfigurations(customConfigurationList);
        final CustomConfigurations customConfigurationsOut = new CustomConfigurations();
        customConfigurationsOut.setCustomConfigurations(customConfigurationListOut);
        
        
        Mockito.when(customConfigurationManager.createCustomConfigurations(customConfigurations)).thenReturn(customConfigurationsOut);
        final CustomConfigurations customConfigurationReturned = customConfigurationService.createCustomConfigurations(customConfigurations);
        assertEquals(2, customConfigurationReturned.getCustomConfigurations().size());
    }
    
}
