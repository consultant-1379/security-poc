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
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExtCACRLManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl.ExtCACRLManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACRLManagementAuthorizationManagerTest {

    @InjectMocks
    ExtCACRLManagementAuthorizationManager extCACRLManagementAuthorizationManager;

    @Mock
    ExtCACRLManagementAuthorizationHandler extCACRLManagementAuthorizationHandler;

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
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.IMPORT);
    }
    
    // Action Type IMPORT is not used
    @Test(expected = IllegalArgumentException.class)
    public void testAauthorizeExternalCRLInfoOperationsException() {
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.IMPORT);
    }
    
    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeIsExternalCANameAvailable() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACRLManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
    }
    
    @Test()
    public void testAuthorizeIsExternalCANameAvailable_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
    }
    
    @Test (expected = IllegalArgumentException.class)
    public void testAuthorizeauthorizeDeleteExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.DELETE);
   }

    
    @Test (expected = IllegalArgumentException.class)
    public void testAuthorizeGetExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.READ);
   }
    
    @Test
    public void testAuthorizeUpdateExternalCA() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(extCACRLManagementAuthorizationHandler).authorizeUpdateExternalCA();
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.UPDATE);
   }
    
    @Test
    public void testAuthorizeUpdateExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.UPDATE);
   }
    
    @Test (expected = IllegalArgumentException.class)
    public void testAuthorizeCreateExternalCA_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.CREATE);
    }
    
    @Test (expected = IllegalArgumentException.class)
    public void testAuthorizeExportExternalCACeritifcate_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.EXPORT);
    }
    
    @Test
    public void testAuthorizeGetExternalCRLInfo() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(extCACRLManagementAuthorizationHandler).authorizeGetExternalCRLInfo();
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.READ);
    }
    
    @Test
    public void testAuthorizeGetExternalCRLInfo_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.READ);
    }
    
    @Test
    public void testAuthorizeUpdateExternalCRLInfo() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(extCACRLManagementAuthorizationHandler).authorizeGetExternalCRLInfo();
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.UPDATE);
    }
    
    @Test
    public void testAuthorizeUpdateExternalCRLInfo_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.UPDATE);
    }
    
    @Test
    public void testAuthorizeDeleteExternalCRLInfo() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(extCACRLManagementAuthorizationHandler).authorizeDeleteExternalCRLInfo();
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.DELETE);
    }
    
    @Test
    public void testAuthorizeDeleteExternalCRLInfo_IsCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.DELETE);
    }
    
}
