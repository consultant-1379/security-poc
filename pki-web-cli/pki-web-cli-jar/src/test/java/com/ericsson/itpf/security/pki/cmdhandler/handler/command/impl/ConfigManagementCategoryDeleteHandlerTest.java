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

import java.io.IOException;
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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementCategoryDeleteHandlerTest {
    private static final String NAME = "name";
    private static final String TESTCATEGORY = "test_Entity_Category";
    private static final String INVALIDCATEGORY = "sjahd";
    private static final String UNDEFINEDCATEGORY = "undefined";

    @Spy
    final private Logger logger = LoggerFactory.getLogger(ConfigManagementCategoryDeleteHandler.class);

    @InjectMocks
    ConfigManagementCategoryDeleteHandler configManagementCategoryDeleteHandler;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliutil;

    @Mock
    SystemRecorder systemRecorder;

    EntityCategory entityCategory = new EntityCategory();
    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;
    Map<String, Object> properties = new HashMap<String, Object>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "CONFIGMANAGEMENTCATEGORYDELETE");
        properties.put(NAME, TESTCATEGORY);
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMANAGEMENTCATEGORYDELETE);
        command.setProperties(properties);

        entityCategory.setName("test_Entity_Category");
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);
    }

    @Test
    public void testProcessCommand_ConfigDeleteCategory() throws IOException {
        logger.info("Testing deletion of entity category");

        Mockito.doNothing().when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configManagementCategoryDeleteHandler.process(command);

        assertEquals(commandResponse.getMessage(), Constants.CATEGORY_DELETED_SUCCESSFULLY);
    }

    @Test
    public void testDeleteEntityCategory_Null() {
        entityCategory.setName(null);

        properties.put("name", null);
        command.setProperties(properties);

        Mockito.doThrow(NullPointerException.class).when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryDeleteHandler.process(command);

        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY)));

    }

    @Test
    public void testEntityCategoryNotFoundException() {

        entityCategory.setName("sjahd");
        properties.put("name", "sjahd");
        command.setProperties(properties);
        final EntityCategoryNotFoundException entityCategoryNotFoundException = new EntityCategoryNotFoundException("Category not found");

        Mockito.doThrow(entityCategoryNotFoundException).when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryDeleteHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage())));
    }

    @Test
    public void testEntityCategoryInUseException() {

        entityCategory.setName("undefined");
        properties.put("name", "undefined");
        command.setProperties(properties);
        final EntityCategoryInUseException entityCategoryInUseException = new EntityCategoryInUseException("Category in use");

        Mockito.doThrow(entityCategoryInUseException).when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryDeleteHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_CATEGORY_INUSE_EXCEPTION.toInt(), entityCategoryInUseException.getMessage())));

    }

    @Test
    public void testProcessCommand_DeleteCategory_SecurityViolationException() {
        logger.info("Testing deletion of entity category");

        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        configManagementCategoryDeleteHandler.process(command);

    }

    @Test
    public void testPKIConfigurationServiceException() {

        entityCategory.setName("sjahd");
        properties.put("name", "sjahd");
        command.setProperties(properties);
        final PKIConfigurationServiceException pkiConfigurationServiceException = new PKIConfigurationServiceException();

        Mockito.doThrow(pkiConfigurationServiceException).when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryDeleteHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(
                CliUtil.buildMessage(ErrorType.PKI_CONFIGURATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION)));
    }

    @Test
    public void testEntityNotFoundException() {

        entityCategory.setName("undefined");
        properties.put("name", "undefined");
        command.setProperties(properties);
        final EntityNotFoundException entityNotFoundException = new EntityNotFoundException("Category in use");

        Mockito.doThrow(entityNotFoundException).when(pkiConfigurationManagementService).deleteCategory(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryDeleteHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNEXPECTED_ERROR.toInt(), Constants.ERROR_WHILE_DELETING)));

    }

}
