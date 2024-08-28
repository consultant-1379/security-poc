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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Map;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.data.CustomConfigurationSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CustomConfigurationMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CustomConfigurationData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

@RunWith(MockitoJUnitRunner.class)
public class CustomConfigurationPersistenceHandlerTest {

    @InjectMocks
    CustomConfigurationPersistenceHandler customConfigurationPersistenceHandler;

    @Mock
    CustomConfigurationMapper customConfigurationMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityData entityData;

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
        customConfiguration = customConfigurationSetUpData.createCustomConfiguration(1, "name", "value", "note", "owner");

        customConfigurationWithNameAndOwner = customConfigurationSetUpData.createCustomConfiguration(0, "name", null, null, "owner");

        customConfigurationWithId = customConfigurationSetUpData.createCustomConfiguration(1, null, null, null, null);

        customConfigurationData = customConfigurationSetUpData.createCustomConfigurationData("name", "value", "note", "owner");
    }

    @Test
    public void testGetCustomConfiguration() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(1, "name", "value", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData);
        when(customConfigurationMapper.toAPIFromModel(customConfigurationData)).thenReturn(customConfiguration2);
        final CustomConfiguration customConfigurationGot = customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationGot.getName());
        assertEquals(customConfiguration.getValue(), customConfigurationGot.getValue());
        assertEquals(customConfiguration.getNote(), customConfigurationGot.getNote());
        assertEquals(customConfiguration.getOwner(), customConfigurationGot.getOwner());
        assertTrue(customConfigurationGot.getId() > 0);
    }

    @Test(expected = CustomConfigurationNotFoundException.class)
    public void testGetCustomConfigurationNotFound() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(null);
        final CustomConfiguration customConfigurationGot = customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration);
    }

    @Test(expected = CustomConfigurationServiceException.class)
    public void testGetCustomConfigurationServiceException() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenThrow(PersistenceException.class);
        final CustomConfiguration customConfigurationGot = customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationGot.getName());
        assertEquals(customConfiguration.getValue(), customConfigurationGot.getValue());
        assertEquals(customConfiguration.getNote(), customConfigurationGot.getNote());
        assertEquals(customConfiguration.getOwner(), customConfigurationGot.getOwner());
        assertTrue(customConfigurationGot.getId() > 0);
    }

    @Test
    public void testCreateCustomConfiguration() throws CustomConfigurationAlreadyExistsException, CustomConfigurationServiceException {
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(1, "name", "value", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(null).thenReturn(customConfigurationData);
        when(customConfigurationMapper.fromAPIToModel(customConfiguration)).thenReturn(customConfigurationData);
        when(customConfigurationMapper.toAPIFromModel(customConfigurationData)).thenReturn(customConfiguration2);
        final CustomConfiguration customConfigurationCreated = customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration);
        assertEquals(customConfiguration.getName(), customConfigurationCreated.getName());
        assertEquals(customConfiguration.getValue(), customConfigurationCreated.getValue());
        assertEquals(customConfiguration.getNote(), customConfigurationCreated.getNote());
        assertEquals(customConfiguration.getOwner(), customConfigurationCreated.getOwner());
        assertTrue(customConfigurationCreated.getId() > 0);
    }

    @Test(expected = CustomConfigurationAlreadyExistsException.class)
    public void testCreateCustomConfigurationAlreadyExists() throws CustomConfigurationAlreadyExistsException, CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData);
        final CustomConfiguration customConfigurationCreated = customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration);
    }

    @Test(expected = CustomConfigurationServiceException.class)
    public void testCreateCustomConfigurationServiceException() throws CustomConfigurationAlreadyExistsException, CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(null);
        Mockito.doThrow(PersistenceException.class).when(persistenceManager).createEntity(Mockito.any(CustomConfigurationData.class));
        final CustomConfiguration customConfigurationCreated = customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration);
    }

    @Test
    public void testUpdateCustomConfiguration() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(0, "name", "value2", "note", "owner");
        final CustomConfigurationData customConfigurationData2 = customConfigurationSetUpData.createCustomConfigurationData("name", "value2", "note", "owner");
        final CustomConfiguration customConfiguration3 = customConfigurationSetUpData.createCustomConfiguration(1, "name", "value2", "note", "owner");
        final CustomConfigurationData customConfigurationData3 = customConfigurationSetUpData.createCustomConfigurationData("name", "value2", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData).thenReturn(customConfigurationData3);
        when(customConfigurationMapper.fromAPIToModel(customConfiguration2)).thenReturn(customConfigurationData2);
        when(customConfigurationMapper.toAPIFromModel(customConfigurationData3)).thenReturn(customConfiguration3);
        final CustomConfiguration customConfigurationUpdated = customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration2);
        assertEquals(customConfiguration2.getName(), customConfigurationUpdated.getName());
        assertEquals(customConfiguration2.getValue(), customConfigurationUpdated.getValue());
        assertEquals(customConfiguration2.getNote(), customConfigurationUpdated.getNote());
        assertEquals(customConfiguration2.getOwner(), customConfigurationUpdated.getOwner());
        assertEquals(customConfigurationUpdated.getId(), 1);
    }

    @Test(expected = CustomConfigurationNotFoundException.class)
    public void testUpdateCustomConfigurationNotFoundException() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(null);
        final CustomConfiguration customConfigurationUpdated = customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration);
    }

    @Test(expected = CustomConfigurationServiceException.class)
    public void testUpdateCustomConfigurationServiceException() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfigurationData customConfigurationData2 = customConfigurationSetUpData.createCustomConfigurationData("name", "value2", "note", "owner");
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(0, "name", "value2", "note", "owner");
        final CustomConfiguration customConfiguration3 = customConfigurationSetUpData.createCustomConfiguration(1, "name", "value2", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData2);
        when(customConfigurationMapper.fromAPIToModel(customConfiguration2)).thenReturn(customConfigurationData2);
        Mockito.doThrow(PersistenceException.class).when(persistenceManager).updateEntity(Mockito.any(CustomConfigurationData.class));
        final CustomConfiguration customConfigurationUpdated = customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration2);
    }

    @Test
    public void testDeleteCustomConfiguration() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(0, "name", "value2", "note", "owner");
        final CustomConfigurationData customConfigurationData2 = customConfigurationSetUpData.createCustomConfigurationData("name", "value2", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData2);
        customConfigurationPersistenceHandler.deleteCustomConfiguration(customConfiguration2);
    }

    @Test(expected = CustomConfigurationNotFoundException.class)
    public void testDeleteCustomConfigurationNotFoundException() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(0, "name", "value2", "note", "owner");
        final CustomConfigurationData customConfigurationData2 = customConfigurationSetUpData.createCustomConfigurationData("name", "value2", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(null);
        customConfigurationPersistenceHandler.deleteCustomConfiguration(customConfiguration2);
    }

    @Test(expected = CustomConfigurationServiceException.class)
    public void testDeleteCustomConfigurationServiceException() throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfiguration customConfiguration2 = customConfigurationSetUpData.createCustomConfiguration(0, "name", "value2", "note", "owner");
        final CustomConfigurationData customConfigurationData2 = customConfigurationSetUpData.createCustomConfigurationData("name", "value2", "note", "owner");
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData2);
        Mockito.doThrow(PersistenceException.class).when(persistenceManager).deleteEntity(Mockito.any(CustomConfigurationData.class));
        customConfigurationPersistenceHandler.deleteCustomConfiguration(customConfiguration2);
    }

    @Test
    public void testIsPresentCustomConfigurationTrue() throws CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(customConfigurationData);
        final boolean isPresent = customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration);
        assertTrue(isPresent);
    }

    @Test
    public void testIsPresentCustomConfigurationFalse() throws CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenReturn(null);
        final boolean isPresent = customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration);
        assertFalse(isPresent);
    }

    @Test(expected = CustomConfigurationServiceException.class)
    public void testIsPresentCustomConfigurationServiceException() throws CustomConfigurationServiceException {
        when(persistenceManager.findEntityWhere(Mockito.eq(CustomConfigurationData.class), Mockito.any(Map.class))).thenThrow(PersistenceException.class);
        final boolean isPresent = customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration);
        assertFalse(isPresent);
    }


}
