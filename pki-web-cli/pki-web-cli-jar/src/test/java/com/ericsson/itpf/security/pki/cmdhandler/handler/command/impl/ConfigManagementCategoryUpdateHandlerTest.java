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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementCategoryUpdateHandlerTest {

    @Spy
    final private Logger logger = LoggerFactory.getLogger(ConfigManagementCategoryUpdateHandler.class);

    @InjectMocks
    ConfigManagementCategoryUpdateHandler configManagementCategoryUpdateHandler;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliutil;

    @Mock
    SystemRecorder systemRecorder;

    EntityCategory entityCategory = new EntityCategory();
    EntityCategory entityCategory_new = new EntityCategory();

    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;
    Map<String, Object> properties = new HashMap<String, Object>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "CONFIGMANAGEMENTCATEGORYUPDATE");
        properties.put("oldname", "test_Entity_Category_old");
        properties.put("newname", "test_Entity_Category_new");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMANAGEMENTCATEGORYUPDATE);
        command.setProperties(properties);

        entityCategory.setName("test_Entity_Category_old");
        entityCategory_new.setName("test_Entity_Category_new");
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);
    }

    @Test
    public void testProcessCommand_ConfigUpdateCategory() throws IOException {

        logger.info("Testing Updation of Entity Category");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenReturn(entityCategory);
        when(pkiConfigurationManagementService.updateCategory(entityCategory)).thenReturn(entityCategory_new);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configManagementCategoryUpdateHandler.process(command);

        assertEquals(commandResponse.getMessage(), Constants.CATEGORY_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testEntityCategoryOldNameNullException() {
        entityCategory.setName("test_Entity_Category_old");
        entityCategory_new.setName(null);
        properties.put("oldname", null);
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenReturn(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryUpdateHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY)));

    }

    @Test
    public void testEntityCategoryNewNameNullException() {
        entityCategory.setName("test_Entity_Category_old");
        entityCategory_new.setName(null);
        properties.put("newname", null);
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenReturn(entityCategory);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryUpdateHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY)));

    }

    @Test
    public void testEntityCategoryNotFoundException() {
        entityCategory.setName("sjahd");
        entityCategory_new.setName("");
        properties.put("newname", "yrtyr");
        properties.put("oldname", "yrtyru");
        command.setProperties(properties);

        Mockito.when(pkiConfigurationManagementService.getCategory(Mockito.any(EntityCategory.class))).thenThrow(EntityCategoryNotFoundException.class);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) configManagementCategoryUpdateHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), null)));

    }

    @Test
    public void test_ConfigUpdateCategory_SecurityViolationException() throws IOException {

        logger.info("Testing Updation of Entity Category");
        when(pkiConfigurationManagementService.getCategory(entityCategory)).thenReturn(entityCategory);
        when(pkiConfigurationManagementService.updateCategory(entityCategory)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        configManagementCategoryUpdateHandler.process(command);

    }
}
