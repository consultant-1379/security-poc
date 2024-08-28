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
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;
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
public class EntityManagemenetCreateHandlerTest {

    @InjectMocks
    EntityManagementCreateHandler entityManagementCreateHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementCreateHandler.class);

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

        properties.put("command", "ENTITYMANAGEMENTCREATE");
        properties.put("entitytype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTCREATE);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("entities.xml");
        entities = JaxbUtil.getObject(url.openStream(), Entities.class);

        caEntity = entities.getCAEntities().get(0);
        entity = entities.getEntities().get(0);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);

    }

    @Test
    public void testProcessCommand_EntityCreateHandler_CAEtity() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity(caEntity)).thenReturn(caEntity);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ENTITY_SUCCESSFUL_INFO);
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_Entity() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity(entity)).thenReturn(entity);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ENTITY_SUCCESSFUL_INFO);
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_NoXml() {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);
        properties.remove("xmlfile");
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);

        assertEquals(commandResponse.getMessage(), "Error: 11101 Input xml file is missing");
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_NoEntities() {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);
        properties.put("xmlfile", null);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11202 No entities found in the imported in the file ");
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_IllegalArgException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new IllegalArgumentException("Inappropriate argument"));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11099 Unexpected Internal Error, please check the error log for more details. Inappropriate argument");
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_RunTimeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new RuntimeException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11099 Unexpected Internal Error, please check the error log for more details."));

    }

    @Test
    public void testProcessCommand_EntityCreateHandler_Entities() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Try createbulk for creating more than one entity");
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_NullEntities() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(null);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "11099 Unexpected Internal Error, please check the error log for more details.");
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_AlgorithmNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new AlgorithmNotFoundException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Provided Algorithm not found, Please check online help for the list of supported algorithms."));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_EntityAlreadyExistsException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new EntityAlreadyExistsException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11203 Invalid Argument Entity already exists"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_EntityCategoryNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new EntityCategoryNotFoundException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: "));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_EntityServiceException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new EntityServiceException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11201 "));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_InvalidEntityAttributeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidEntityAttributeException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11206"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_InvalidEntityCategoryException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidEntityCategoryException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11214"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_InvalidProfileException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidProfileException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11105"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_InvalidSubjectAltNameExtension() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidSubjectAltNameExtension(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11345"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_InvalidSubjectException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new InvalidSubjectException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11334"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_MissingMandatoryFieldException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new MissingMandatoryFieldException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11332"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_ProfileNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new ProfileNotFoundException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("11103 No profile(s) found, try with valid Profile"));
    }

    @Test
    public void testProcessCommand_EntityCreateHandler_CommonRuntimeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(new CommonRuntimeException(""));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);

        assertEquals(commandResponse.getMessage(), "Error: 11101 Invalid xml format found, Please see online help for correct xml format");
    }

    @Test
    public void test_EntityCreateHandler_CAEtity_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity(caEntity)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementCreateHandler.process(command);
    }

    @Test
    public void test_EntityCreateHandler_Entity_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity_v1(entity)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementCreateHandler.process(command);
    }

    @Test
    public void test_EntityCreateHandler_Entity_OTPException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity_v1(entity)).thenThrow(new OTPException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11240"));
    }

    @Test
    public void test_EntityCreateHandler_Entity_CRLExtensionException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity_v1(entity)).thenThrow(new CRLExtensionException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11349"));
    }

    @Test
    public void test_EntityCreateHandler_Entity_InvalidCRLGenerationInfoException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity_v1(entity)).thenThrow(new InvalidCRLGenerationInfoException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11350"));
    }

    @Test
    public void test_EntityCreateHandler_Entity_InvalidEntityException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity_v1(entity)).thenThrow(new InvalidEntityException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11205 Parameters in the entity are invalid."));
    }

    @Test
    public void test_EntityCreateHandler_Entity_UnsupportedCRLVersionException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementCreateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.createEntity_v1(entity)).thenThrow(new UnsupportedCRLVersionException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementCreateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11351"));
    }
}
