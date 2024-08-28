/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementDeleteHandlerTest {

    @InjectMocks
    EntityManagementDeleteHandler entityManagementDeleteHandler;

    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementDeleteHandler.class);

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;
    Entities entities = new Entities();
    CAEntity caEntity = new CAEntity();
    Entity entity = new Entity();
    Map<String, Object> properties = new HashMap<String, Object>();
    List<AbstractEntity> entitiesList = new ArrayList<AbstractEntity>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "ENTITYMANAGEMENTDELETE");
        properties.put("entitytype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTDELETE);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("entities.xml");
        entities = JaxbUtil.getObject(url.openStream(), Entities.class);

        caEntity = entities.getCAEntities().get(0);
        entity = entities.getEntities().get(0);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);

    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_CAEtity() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        entities.setEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Entity with name:: RootCA_127 successfully deleted ");
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_Entity() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Entity with name:: ERBS_13 successfully deleted ");
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_ByNameAndType() {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.remove("xmlfile");

        properties.put("name", "enmserviceentity");
        properties.put("entitytype", "ee");

        entitiesList.add(entity);
        when(commandHandlerUtils.getEntityType("ee")).thenReturn(EntityType.ENTITY);
        when(commandHandlerUtils.getEntityInstance(EntityType.ENTITY, "enmserviceentity")).thenReturn(entity);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Entity with name:: ERBS_13 successfully deleted ");
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_NoXml() {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);
        properties.remove("xmlfile");
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Unable to delete the entity. EntityName and entityType is mandatory Parameters");
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_NoEntities() {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);
        properties.put("xmlfile", null);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11202 No entities are found in system");
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_Entities() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ENTITY_DELETED_SUCCESSFULLY);
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_RuntimeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new RuntimeException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11099 Error while deleting entity"));
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_All() {

        MockitoAnnotations.initMocks(entityManagementDeleteHandler);
        properties.put("all", "all");
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Unable to delete the entity. EntityName and entityType is mandatory Parameters");
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_EntityNotFound() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);

        assertTrue(commandResponse.getMessage().contains("Error: 11204 No entity found with matching criteria"));
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_CommonRuntimeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new CommonRuntimeException("invalid xml"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);

        assertEquals(commandResponse.getMessage(), "Error: 11101 Invalid xml format found, Please see online help for correct xml format");
    }

    @Test
    @Ignore
    public void testProcessCommand_EntityDeleteHandler_EntityInUseException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new EntityInUseException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);

        assertTrue(commandResponse.getMessage().contains("Error: 11206 Error while deleting entity"));
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_EntityServiceException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new EntityServiceException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11201 Error while deleting entity"));
    }

     @Test
    public void testProcessCommand_EntityDeleteHandler_InvalidEntityException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidEntityException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error while deleting entity"));
    }

    @Test
    public void testProcessCommand_EntityDeleteHandler_InvalidEntityAttributeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidEntityAttributeException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementDeleteHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error while deleting entity"));
    }
    @Test
    public void test_EntityDeleteHandler_CAEtity_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementDeleteHandler);

        entities.setEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        Mockito.doThrow(SecurityViolationException.class).when(entityManagementService).deleteEntities(entities);
        entityManagementDeleteHandler.process(command);
    }
}
