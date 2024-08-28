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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementImportHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityManagementImportHandlerTest.class);

    @InjectMocks
    EntityManagementImportHandler entityManagementImportHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;

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

        properties.put("command", "ENTITYMANAGEMENTIMPORT");
        properties.put("entitytype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTIMPORT);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("entities.xml");
        entities = JaxbUtil.getObject(url.openStream(), Entities.class);
        properties.put("xmlfile", entities);

        caEntity = entities.getCAEntities().get(0);
        entity = entities.getEntities().get(0);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);
    }

    @Test
    public void testProcessCommand_EntityImportHandler() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), Constants.ENTITIES_SUCCESSFUL_INFO);
    }

    @Test
    public void testProcessCommand_EntityImportHandler_NullEntities() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(null);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11202 Entity Information is missing in the XML file");
    }

    @Test
    public void testProcessCommand_EntityImportHandler_IllegalArgumentException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new IllegalArgumentException("Illegal Argument")).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage().toString(), "Error: 11099 Unexpected Internal Error, please check the error log for more details.Illegal Argument");
    }

    @Test
    public void testProcessCommand_EntityImportHandler_AlgorithmNotFoundException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new AlgorithmNotFoundException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Provided Algorithm not found, Please check online help for the list of supported algorithms."));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_EntityExsist() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new EntityAlreadyExistsException("Invalid Argument Entity already exists")).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Invalid Argument Entity already exists"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_EntityCategoryNotFoundException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new EntityCategoryNotFoundException("category is not found")).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("category is not found"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_EntityServiceException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new EntityServiceException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11201"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_InvalidEntityAttributeException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new InvalidEntityAttributeException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11206"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_InvalidEntityCategoryException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        Mockito.doThrow(new InvalidEntityCategoryException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11214"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_InvalidProfileException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new InvalidProfileException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11105"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_InvalidSubjectAltNameExtension() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new InvalidSubjectAltNameExtension()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11345"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_InvalidSubjectException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new InvalidSubjectException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11334"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_MissingMandatoryFieldException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new MissingMandatoryFieldException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11332"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_ProfileNotFound() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new ProfileNotFoundException()).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11103 No profile(s) found, try with valid Profile"));
    }

    @Test
    public void testProcessCommand_EntityImportHandler_CommonRuntimeException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new CommonRuntimeException(null)).when(entityManagementService).importEntities((Entities) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11101 Invalid xml format found"));
    }

    @Test
    public void test_EntityImportHandler_SecurityViolationException() throws IOException {

        MockitoAnnotations.initMocks(entityManagementImportHandler);
        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(entityManagementService).importEntities((Entities) Mockito.anyObject());
        entityManagementImportHandler.process(command);
    }

}
