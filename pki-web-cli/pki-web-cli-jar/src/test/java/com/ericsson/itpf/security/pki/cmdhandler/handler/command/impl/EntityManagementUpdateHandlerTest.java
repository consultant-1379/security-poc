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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
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
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementUpdateHandlerTest {

    @InjectMocks
    EntityManagementUpdateHandler entityManagementUpdateHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    private Logger logger = LoggerFactory.getLogger(EntityManagementUpdateHandler.class);

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

        properties.put("command", "ENTITYMANAGEMENTUPDATE");
        properties.put("entitytype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTUPDATE);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("entities.xml");
        entities = JaxbUtil.getObject(url.openStream(), Entities.class);

        caEntity = entities.getCAEntities().get(0);
        entity = entities.getEntities().get(0);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);


    }

    @Test
    public void testProcessCommand_EntityUpdateHandler_CAEntity() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity_v1(caEntity)).thenReturn(caEntity);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Entity with name:: RootCA_127 is sucessfully updated");
    }

    @Test
    public void testProcessCommand_EntityUpdateHandler_Entity() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity_v1(entity)).thenReturn(entity);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Entity with name:: ERBS_13 is sucessfully updated");
    }

    @Test
    public void testProcessCommand_EntityUpdateHandler_NoXml() {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);
        properties.remove("xmlfile");
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.INPUT_FILE_MISSING);

    }

    @Test
    public void testProcessCommand_EntityUpdateHandler_NoEntities() {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);
        properties.put("xmlfile", null);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.NO_ENTITIES_FOUND_IN_XML);
    }

    @Test
    public void testProcessCommand_EntityUpdateHandler_EntityCategoryNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        Mockito.doNothing().when((entityManagementService)).updateEntities((Entities) Mockito.anyObject());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ENTITY_GOT_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testProcessCommand_EntityUpdateHandler_EntityServiceException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity(caEntity)).thenThrow(new EntityServiceException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_EntityCategoryNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(EntityCategoryNotFoundException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_AlgorithmNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(AlgorithmNotFoundException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_CRLExtensionException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(CRLExtensionException.class);
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidCRLGenerationInfoException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidCRLGenerationInfoException.class);
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidEntityException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidEntityException.class);
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidProfileException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidProfileException.class);
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidSubjectException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidSubjectException.class);
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_UnsupportedCRLVersionException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(UnsupportedCRLVersionException.class);
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }


    @Test
    public void testProcessCommand_EntityAlreadyExistsException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(EntityAlreadyExistsException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_EntityNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(EntityNotFoundException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_EntityServiceException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(EntityServiceException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidEntityAttributeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidEntityAttributeException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidEntityCategoryException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidEntityCategoryException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_InvalidSubjectAltNameExtension() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(InvalidSubjectAltNameExtension.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_MissingMandatoryFieldException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(MissingMandatoryFieldException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_ProfileNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(ProfileNotFoundException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessCommand_CommonRuntimeException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenThrow(CommonRuntimeException.class);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void test_EntityUpdateHandler_CAEntity_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(caEntity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity(caEntity)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementUpdateHandler.process(command);
    }

    @Test
    public void test_EntityUpdateHandler_Entity_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity_v1(entity)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementUpdateHandler.process(command);
    }

    @Test
    public void test_EntityUpdateHandler_CRLGenerationException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity_v1(entity)).thenThrow(new CRLGenerationException(PkiErrorCodes.CRL_GENERATION_FAILED));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11002 Exception occured during CRL generation. CRL generation failed."));
    }

    @Test
    public void test_EntityUpdateHandler_OTPException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);

        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity_v1(entity)).thenThrow(new OTPException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11240"));
    }

    @Test
    public void test_EntityUpdateHandler_EntityServiceException() throws IOException {
        MockitoAnnotations.initMocks(entityManagementUpdateHandler);
        entities.setCAEntities(null);
        properties.put("xmlfile", entities);

        when(commandHandlerUtils.getUpdatedEntitiesFromInputXml(command)).thenReturn(entities);

        entitiesList.add(entity);
        when(commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities())).thenReturn(entitiesList);
        when(entityManagementService.updateEntity_v1(entity)).thenThrow(new EntityServiceException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) entityManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11201  Internal service error occurred Suggested Solution :  retry"));
    }
}
