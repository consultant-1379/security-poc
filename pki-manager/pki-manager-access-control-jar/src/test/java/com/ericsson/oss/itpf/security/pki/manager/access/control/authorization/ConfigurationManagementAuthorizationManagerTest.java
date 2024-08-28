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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ConfigurationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.configuration.ConfigurationManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationManagementAuthorizationManagerTest {

    @InjectMocks
    ConfigurationManagementAuthorizationManager configurationManagementAuthorizationManager;

    @Mock
    ConfigurationManagementAuthorizationHandler configurationManagementAuthorizationHandler;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    ContextUtility contextUtility;

    @Test
    public void testAuthorizeGetAlgorithm() {

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeGetAlgorithm();
        configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.READ);

    }

    @Test
    public void testAuthorizeUpdateAlgorithm() {

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeUpdateAlgorithm();
        configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.UPDATE);

    }

    @Test
    public void testAuthorizeCreateEntityCategory() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeCreateEntityCategory();
        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.CREATE);

    }

    @Test
    public void testAuthorizeUpdateEntityCategory() {

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeUpdateEntityCategory();
        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.UPDATE);

    }

    @Test
    public void testAuthorizeDeleteEntityCategory() {

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeDeleteEntityCategory();
        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.DELETE);

    }

    @Test
    public void testAuthorizeGetEntityCategory() {

        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeGetEntityCategory();
        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.READ);

    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeIsCategoryNameAvailable() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        configurationManagementAuthorizationManager.authorizeIsCategoryNameAvailable();
    }

    @Test
    public void testAuthorizeGetCustomConfiguration() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeGetCustomConfiguration();
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.READ);

    }

    @Test
    public void testAuthorizeUpdateCustomConfiguration() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeUpdateCustomConfiguration();
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.UPDATE);

    }

    @Test
    public void testAuthorizeCreateCustomConfiguration() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);

        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeCreateCustomConfiguration();
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.CREATE);

    }

    @Test
    public void testAuthorizeDeleteCustomConfiguration() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(configurationManagementAuthorizationHandler).authorizeDeleteCustomConfiguration();
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.DELETE);

    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeIsPresetCustomConfiguration() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        configurationManagementAuthorizationManager.authorizeIsPresentCustomConfiguration();
    }

}
