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

import java.net.URL;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementListHandlerTest {

    @InjectMocks
    EntityManagementListHandler entityManagementListHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliutil;

    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementListHandler.class);

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

        properties.put("command", "ENTITYMANAGEMENTLIST");
        properties.put("entitytype", "ca");
        properties.put("name", "ENMServiceCA");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTLIST);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("entities.xml");
        entities = JaxbUtil.getObject(url.openStream(), Entities.class);

        caEntity = entities.getCAEntities().get(0);
        entity = entities.getEntities().get(0);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);

    }

    @Test
    public void testProcessCommand_EntityListHandler_CAEtity() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenReturn(caEntity);
        when(entityManagementService.getEntity(caEntity)).thenReturn(caEntity);
        when(commandHandlerUtils.setEntities(EntityType.CA_ENTITY, entitiesList)).thenReturn(entities);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenCallRealMethod();
        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) entityManagementListHandler.process(command);
        assertEquals(commandResponse.getValueSize(), 3);
    }

    @Test
    public void testProcessCommand_EntityListHandler_EntityNotFound() {
        MockitoAnnotations.initMocks(entityManagementListHandler);
        properties.put("name", "ENMService");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTLIST);
        command.setProperties(properties);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);
        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMService")).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Entity not Found, try with valid Entity"));
    }

    @Test
    public void testProcessCommand_EntityListHandler_IllegalArgumentException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new IllegalArgumentException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error while listing"));

    }

    @Test
    public void testProcessCommand_EntityListHandler_EntityServiceException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new EntityServiceException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessCommand_EntityListHandler_EntityCategoryNotFoundException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new EntityCategoryNotFoundException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Entity not Found, try with valid Entity"));
    }

    @Test
    public void testProcessCommand_EntityListHandler_InvalidEntityAttributeException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new InvalidEntityAttributeException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Parameters in the entity are invalid."));
    }

    @Test
    public void testProcessCommand_EntityListHandler_InvalidEntityCategoryException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new InvalidEntityCategoryException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);

        assertTrue(commandResponse.getMessage().contains("Error: 11214"));
    }

    @Test
    public void testProcessCommand_EntityListHandler_InvalidEntityException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new InvalidEntityException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Parameters in the entity are invalid"));
    }

    @Test
    public void testProcessCommand_EntityListHandler_ProfileNotFoundException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new ProfileNotFoundException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11099 Error while listing"));
    }

    @Test
    public void testProcessCommand_EntityListHandler_CommandSyntaxException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenThrow(new CommandSyntaxException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11001 Command syntax error"));
    }

    @Test
    public void testProcessCommand_EntityListHandler_EmptyEntityName() {
        MockitoAnnotations.initMocks(entityManagementListHandler);
        properties.put("command", "ENTITYMANAGEMENTLIST");
        properties.put("entitytype", "ca");
        properties.put("name", "");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTLIST);
        command.setProperties(properties);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11000 Entity Name cannot be null or empty."));
    }

    @Test
    public void test_EntityListHandler_CAEtity_SecurityViolationException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);

        when(commandHandlerUtils.getEntityType("ca")).thenReturn(EntityType.CA_ENTITY);

        entitiesList.add(caEntity);

        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENMServiceCA")).thenReturn(caEntity);
        when(entityManagementService.getEntity(caEntity)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementListHandler.process(command);
    }

    @Test
    public void test_EntityListHandler_Entity_SecurityViolationException() {
        MockitoAnnotations.initMocks(entityManagementListHandler);
        properties.put("command", "ENTITYMANAGEMENTLIST");
        properties.put("entitytype", "ee");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTLIST);
        command.setProperties(properties);

        when(commandHandlerUtils.getEntityType("ee")).thenReturn(EntityType.ENTITY);

        entitiesList.add(entity);
        when(entityManagementService.getEntities(EntityType.ENTITY)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementListHandler.process(command);
    }
}
