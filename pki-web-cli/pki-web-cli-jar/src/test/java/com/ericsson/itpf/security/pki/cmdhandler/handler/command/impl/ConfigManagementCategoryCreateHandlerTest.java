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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementCategoryCreateHandlerTest {
    private static final String EMPTY = " ";
    private static final String NAME = "name";
    private static final String TESTCATEGORY = "test_Entity_Category";
    private static final String INVALIDCATEGORY = "#!$^#^";

    @Spy
    final private Logger logger = LoggerFactory.getLogger(ConfigManagementCategoryCreateHandler.class);

    @InjectMocks
    ConfigManagementCategoryCreateHandler configManagementCategoryCreateHandler;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliutil;

    @Mock
    EntityCategory entityCategory2;

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

        properties.put("command", "CONFIGMANAGEMENTCATEGORYCREATE");
        properties.put(NAME, TESTCATEGORY);
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMANAGEMENTCATEGORYCREATE);
        command.setProperties(properties);

        entityCategory.setId(3);
        entityCategory.setModifiable(true);
        entityCategory.setName(TESTCATEGORY);
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);
    }

    @Test
    public void testProcessCommand_ConfigCreateCategory() throws IOException {
        logger.info("Testing Creation of Entity Category");

        when(pkiConfigurationManagementService.createCategory(entityCategory)).thenReturn(entityCategory);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configManagementCategoryCreateHandler.process(command);

        assertEquals(commandResponse.getMessage(), Constants.CATEGORY_CREATED_SUCCESSFULLY);
    }

    @Test
    public void testEntityCategory_Null() {
        entityCategory.setName(null);
        properties.put("name", null);
        command.setProperties(properties);

        when(pkiConfigurationManagementService.createCategory(entityCategory)).thenThrow(new NullPointerException());
        when(cliutil.prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY, null)).thenThrow(new NullPointerException());

        configManagementCategoryCreateHandler.process(command);

    }

    @Test
    public void testInvalidEntityCategoryException() {

        entityCategory.setName(" ");
        properties.put("name", " ");
        command.setProperties(properties);

        when(pkiConfigurationManagementService.createCategory(Mockito.any(EntityCategory.class))).thenThrow(InvalidEntityCategoryException.class);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryCreateHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), null)));
    }

    @Test
    public void testEntityCategoryAlreadyExistsException() {

        entityCategory.setName("test_Entity_Category");
        properties.put("name", "test_Entity_Category");
        command.setProperties(properties);

        when(pkiConfigurationManagementService.createCategory(Mockito.any(EntityCategory.class))).thenThrow(EntityCategoryAlreadyExistsException.class);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryCreateHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_CATEGORY_ALREADY_EXIST_EXCEPTION.toInt(), null)));
    }

    @Test
    public void testPKIConfigurationServiceException() {

        entityCategory.setName("#!$^#^");
        properties.put("name", "ewuhe");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.createCategory(Mockito.any(EntityCategory.class))).thenThrow(PKIConfigurationServiceException.class);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryCreateHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(" retry"));

    }

    @Test
    public void test_Create_EntityCategory_SecurityViolationException() {
        logger.info("Testing Creation of Entity Category");

        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(pkiConfigurationManagementService).createCategory(entityCategory);

        configManagementCategoryCreateHandler.process(command);

    }

}
