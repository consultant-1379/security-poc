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
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ProfileManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.ProfileAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementAuthorizationManagerTest {

    @InjectMocks
    ProfileManagementAuthorizationManager profileManagementAuthorization;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    ProfileAuthorizationHandler profileAuthorizationHandler;

    @Mock
    ContextService ctxService;

    @Mock
    ContextUtility contextUtility;

    @Test
    public void testAuthorizeTrustProfileOperations_Create() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(profileAuthorizationHandler).authorizeCreateProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.CREATE);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Create_CREDM_CONTEXT_VALUE() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        profileAuthorizationHandler.authorizeCreateProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.CREATE);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Update() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(profileAuthorizationHandler).authorizeUpdateProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Update_CREDM_CONTEXT_VALUE() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        profileAuthorizationHandler.authorizeUpdateProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Get() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(profileAuthorizationHandler).authorizeGetProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Get_CREDM_CONTEXT_VALUE() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        profileAuthorizationHandler.authorizeGetProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Get_NSCS_CONTEXT_VALUE() {

        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        profileAuthorizationHandler.authorizeGetProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Delete() {
        profileAuthorizationHandler.authorizeDeleteProfile();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.DELETE);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Import() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(profileAuthorizationHandler).authorizeImportProfiles();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.IMPORT);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Import_CREDM_CONTEXT_VALUE() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        profileAuthorizationHandler.authorizeImportProfiles();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.IMPORT);
    }

    @Test
    public void testAuthorizeTrustProfileOperations_Export() {
        Mockito.doNothing().when(profileAuthorizationHandler).authorizeExportProfiles();
        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);
    }

    @Test
    public void testAuthorize_IsProfileNameAvailable() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        profileManagementAuthorization.authorizeIsProfileNameAvailable();
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorize_IsProfileNameAvailable_CREDM_CONTEXT() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        profileManagementAuthorization.authorizeIsProfileNameAvailable();
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorize_IsProfileNameAvailable_NSCS_CONTEXT() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        profileManagementAuthorization.authorizeIsProfileNameAvailable();
    }

}
