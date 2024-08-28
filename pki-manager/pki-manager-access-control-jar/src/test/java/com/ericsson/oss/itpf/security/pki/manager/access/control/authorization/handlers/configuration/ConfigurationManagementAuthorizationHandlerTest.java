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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.configuration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.configuration.ConfigurationManagementAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationManagementAuthorizationHandlerTest {

    @InjectMocks
    ConfigurationManagementAuthorizationHandler configurationManagementAuthorizationHandler;

    @Mock
    Logger logger;

    @Test
    public void testAuthorizeGetAlgorithm() {
        configurationManagementAuthorizationHandler.authorizeGetAlgorithm();
    }

    @Test
    public void testAuthorizeUpdateAlgorithm() {
        configurationManagementAuthorizationHandler.authorizeUpdateAlgorithm();
    }

    @Test
    public void testAuthorizeCreateEntityCategory() {
        configurationManagementAuthorizationHandler.authorizeCreateEntityCategory();
    }

    @Test
    public void testAuthorizeUpdateEntityCategory() {
        configurationManagementAuthorizationHandler.authorizeUpdateEntityCategory();
    }

    @Test
    public void testAuthorizeDeleteEntityCategory() {
        configurationManagementAuthorizationHandler.authorizeDeleteEntityCategory();
    }

    @Test
    public void testAuthorizeGetEntityCategory() {
        configurationManagementAuthorizationHandler.authorizeGetEntityCategory();
    }

    @Test
    public void testAuthorizeCreateCustomConfiguration() {
        configurationManagementAuthorizationHandler.authorizeCreateCustomConfiguration();
    }

    @Test
    public void testAuthorizeUpdateCustomConfiguration() {
        configurationManagementAuthorizationHandler.authorizeUpdateCustomConfiguration();
    }

    @Test
    public void testAuthorizeDeleteCustomConfiguration() {
        configurationManagementAuthorizationHandler.authorizeDeleteCustomConfiguration();
    }

    @Test
    public void testAuthorizeGetCustomConfiguration() {
        configurationManagementAuthorizationHandler.authorizeGetCustomConfiguration();
    }

}
