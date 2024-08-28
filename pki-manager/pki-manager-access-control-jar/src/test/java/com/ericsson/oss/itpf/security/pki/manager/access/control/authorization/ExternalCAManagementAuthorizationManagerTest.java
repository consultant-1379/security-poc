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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExternalCAManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.ExternalCAAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

@RunWith(MockitoJUnitRunner.class)
public class ExternalCAManagementAuthorizationManagerTest {

    @InjectMocks
    ExternalCAManagementAuthorizationManager externalCAManagementAuthorizationManager;

    @Mock
    ExternalCAAuthorizationHandler externalCAEntityAuthorizationHandler;

    @Mock
    ContextUtility contextUtility;

    @Mock
    ContextService ctxService;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    // Action Type IMPORT is not used
    @Test(expected = IllegalArgumentException.class)
    public void testAuthorizeExternalCAOperationsException() {
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.IMPORT);
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeIsExternalCANameAvailable() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        externalCAManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
    }

    @Test()
    public void testAuthorizeIsExternalCANameAvailable_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        externalCAManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
    }

    @Test
    public void testAuthorizeauthorizeDeleteExternalCA() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(externalCAEntityAuthorizationHandler).authorizeDeleteExternalCA();
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.DELETE);
    }

    @Test
    public void testAuthorizeauthorizeDeleteExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.DELETE);
    }

    @Test
    public void testAuthorizeGetExternalCA() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(externalCAEntityAuthorizationHandler).authorizeGetExternalCA();
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeGetExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeUpdateExternalCA() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(externalCAEntityAuthorizationHandler).authorizeUpdateExternalCA();
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeUpdateExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeCreateExternalCA() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(externalCAEntityAuthorizationHandler).authorizeCreateExternalCA();
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.CREATE);
    }

    @Test
    public void testAuthorizeCreateExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.CREATE);
    }

    @Test
    public void testAuthorizeExportExternalCACeritifcate() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(externalCAEntityAuthorizationHandler).authorizeExportExternalCACeritifcate();
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.EXPORT);
    }

    @Test
    public void testAuthorizeExportExternalCACeritifcate_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.EXPORT);
    }
}
