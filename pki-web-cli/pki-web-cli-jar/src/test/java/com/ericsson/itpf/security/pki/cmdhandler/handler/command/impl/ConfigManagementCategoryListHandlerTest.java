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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementCategoryListHandlerTest {

    @Spy
    final private Logger logger = LoggerFactory.getLogger(ConfigManagementCategoryListHandler.class);

    @InjectMocks
    ConfigManagementCategoryListHandler configManagementCategoryListHandler;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliutil;

    @Mock
    SystemRecorder systemRecorder;

    EntityCategory entityCategory = new EntityCategory();
    List<EntityCategory> entityCategoryList = new ArrayList<EntityCategory>();

    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;
    Map<String, Object> properties = new HashMap<String, Object>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "CONFIGMANAGEMENTCATEGORYLIST");
        properties.put("name", "test_Entity_Category");
        properties.put("modifiable", "false");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMANAGEMENTCATEGORYLIST);
        command.setProperties(properties);

        entityCategory.setModifiable(false);
        entityCategory.setName("test_Entity_Category");

        entityCategoryList.add(entityCategory);
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);
    }

    @Test
    public void testProcessCommand_ConfigListCategory_ByName() throws IOException {

        logger.info("Testing listing of entity category by name");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenReturn(entityCategory);

        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) configManagementCategoryListHandler.process(command);

        assertEquals(commandResponse.getValueSize(), 1);
    }

    @Test
    public void testProcessCommand_ConfigListCategory_ByModifiable() throws IOException {

        logger.info("Testing listing of entity category by modifiable");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenReturn(entityCategory);

        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) configManagementCategoryListHandler.process(command);

        assertEquals(commandResponse.getValueSize(), 1);
    }

    @Test
    public void testProcessCommand_ConfigListCategory() throws IOException {

        final Map<String, Object> properties = new HashMap<String, Object>();
        command = new PkiPropertyCommand();
        command.setProperties(properties);

        when(pkiConfigurationManagementService.listAllEntityCategories()).thenReturn(entityCategoryList);

        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) configManagementCategoryListHandler.process(command);

        assertEquals(commandResponse.getValueSize(), 1);
    }

    @Test
    public void testEntityCategory_Null() {
        entityCategory.setName(null);
        properties.put("name", null);
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryListHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY)));

    }

    @Test
    public void testEntityCategoryNotFoundException() {
        entityCategory.setName("!#@!$%");
        properties.put("name", "!#@!$%");
        command.setProperties(properties);
        logger.info("Testing listing of entity category by name");
        final EntityCategoryNotFoundException entityCategoryNotFoundException = new EntityCategoryNotFoundException();
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenThrow(new EntityCategoryNotFoundException());

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryListHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), null)));

    }

    @Test
    public void test_ConfigListCategory_ByName_SecurityViolationException() {

        logger.info("Testing listing of entity category by name");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        configManagementCategoryListHandler.process(command);

    }

    @Test
    public void test_ConfigListCategory_ByModifiable_SecurityViolationException() {

        logger.info("Testing listing of entity category by modifiable");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        configManagementCategoryListHandler.process(command);

    }

    @Test
    public void test_ConfigListCategory_SecurityViolationException() {

        final Map<String, Object> properties = new HashMap<String, Object>();
        command = new PkiPropertyCommand();
        command.setProperties(properties);

        when(pkiConfigurationManagementService.listAllEntityCategories()).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        configManagementCategoryListHandler.process(command);

    }

    @Test
    public void testPKIConfigurationServiceException() {
        entityCategory.setName("!#@!$%");
        properties.put("name", "!#@!$%");
        command.setProperties(properties);
        logger.info("Testing listing of entity category by name");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenThrow(new PKIConfigurationServiceException());

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryListHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.PKI_CONFIGURATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR)));

    }

    @Test
    public void testEntityNotFoundException() {
        entityCategory.setName("!#@!$%");
        properties.put("name", "!#@!$%");
        command.setProperties(properties);
        logger.info("Testing listing of entity category by name");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenThrow(new EntityNotFoundException());

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryListHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNEXPECTED_ERROR.toInt(), Constants.ERROR_WHILE_LISTING)));

    }

}
