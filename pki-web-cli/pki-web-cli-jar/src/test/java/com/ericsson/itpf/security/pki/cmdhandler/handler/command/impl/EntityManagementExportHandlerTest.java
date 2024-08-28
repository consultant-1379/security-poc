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

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementExportHandlerTest {

    @InjectMocks
    EntityManagementExportHandler entityManagementExportHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityManagementExportHandlerTest.class);

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    CliUtil cliUtil;

    @Mock
    EntityManagementService managementService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    List<String> validCommands;
    List<String> invalidCommands;
    PkiPropertyCommand command;
    Entities entity = new Entities();
    Map<String, Object> properties = new HashMap<String, Object>();
    CAEntity caEntity = new CAEntity();
    CertificateAuthority certificateAuthority = new CertificateAuthority();
    Entities entities = new Entities();
    List<CAEntity> cAEntities = new ArrayList<CAEntity>();
    final List<CAEntity> entitiesList = new ArrayList<CAEntity>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "ENTITYMANAGEMENTEXPORT");
        properties.put("entitytype", "all");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTEXPORT);
        command.setProperties(properties);

        final URL url = getClass().getClassLoader().getResource("entities.xml");
        entity = JaxbUtil.getObject(url.openStream(), Entities.class);

        certificateAuthority.setId(1);
        certificateAuthority.setName("ENmRootCA");
        caEntity.setCertificateAuthority(certificateAuthority);

        cAEntities.add(caEntity);
        entities.setCAEntities(cAEntities);
        entitiesList.add(caEntity);

        Mockito.doNothing().when((exportedItemsHolder)).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(managementService);

    }

    @Test
    public void testProcess_EntityExportHandler_CAEntity() {
        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(managementService.getEntities(EntityType.CA_ENTITY)).thenReturn(entity);
        Mockito.when(managementService.getEntitiesForImport(EntityType.CA_ENTITY)).thenReturn(entity);
        final PkiCommandResponse pkiCommandResponse = entityManagementExportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcess_EntityExportHandler_Entity() {
        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.ENTITY);
        Mockito.when(managementService.getEntities(EntityType.ENTITY)).thenReturn(entity);
        Mockito.when(managementService.getEntitiesForImport(EntityType.ENTITY)).thenReturn(entities);
        final PkiCommandResponse pkiCommandResponse = entityManagementExportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcess_EntityExportHandler_Exception() {
        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(managementService.getEntities(EntityType.CA_ENTITY)).thenThrow(new RuntimeException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11202 Entity not Found, try with valid Entity"));
    }

    @Test
    public void testAbstract_EntityExportHandler() {

        properties.put("entitytype", "ca");
        properties.put("name", "ENmRootCA");

        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.CA_ENTITY);
        when(commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "ENmRootCA")).thenReturn(caEntity);
        Mockito.when(managementService.getEntity(caEntity)).thenReturn(caEntity);
        Mockito.when(managementService.getEntityForImport(caEntity)).thenReturn(caEntity);
        when(commandHandlerUtils.setEntities(EntityType.CA_ENTITY, entitiesList)).thenReturn(entities);
        final PkiCommandResponse pkiCommandResponse = entityManagementExportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    @Ignore
    public void processCommand_EntityExportHandler_All() {
        MockitoAnnotations.initMocks(entityManagementExportHandler);

        properties.put("all", "all");
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementExportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11001 Command syntax error : EntityType ALL is not supported");
    }

    @Test
    @Ignore
    public void testProcess_EntityExportHandler_EntityNotFoundException() {
        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(managementService.getEntities(EntityType.CA_ENTITY)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11205 Entity not Found, try with valid Entity"));
    }

    @Test
    public void testProcess_EntityExportHandler_EntityServiceException() {

        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(managementService.getEntities(EntityType.CA_ENTITY)).thenThrow(new EntityServiceException());
        Mockito.when(managementService.getEntitiesForImport(EntityType.CA_ENTITY)).thenThrow(new EntityServiceException());
        PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void test_EntityExportHandler_CAEntity_SecurityViolationException() {
        MockitoAnnotations.initMocks(entityManagementExportHandler);
        Mockito.when(commandHandlerUtils.getEntityType(Mockito.anyString())).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(managementService.getEntities(EntityType.CA_ENTITY)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        entityManagementExportHandler.process(command);

    }
}
