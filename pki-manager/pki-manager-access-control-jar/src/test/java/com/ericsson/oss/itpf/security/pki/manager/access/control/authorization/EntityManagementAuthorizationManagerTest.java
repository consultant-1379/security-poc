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
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.EntityManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.CAEntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.EntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementAuthorizationManagerTest {

    @InjectMocks
    EntityManagementAuthorizationManager entityManagementAuthorizationManager;

    @Mock
    CAEntityAuthorizationHandler caEntityAuthorizationHandler;

    @Mock
    EntityAuthorizationHandler entityAuthorizationHandler;

    @Mock
    ContextUtility contextUtility;

    @Mock
    ContextService ctxService;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testAuthorizeCAEntityOperations_Import() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeImportEntities();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.IMPORT);

    }

    @Test
    public void testAuthorizeCAEntityOperations_Import_CREDM_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.IMPORT);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Import_NSCS_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.IMPORT);
    }

    @Test
    public void testAuthorizeEntityOperations_Import() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeImportEntities();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.IMPORT);

    }

    @Test
    public void testAuthorizeEntityOperations_Import_CREDM_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.IMPORT);
    }

    @Test
    public void testAuthorizeEntityOperations_Import_NSCS_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.IMPORT);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Create() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeCreateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.CREATE);

    }

    @Test
    public void testAuthorizeCAEntityOperations_Create_CREDM_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.CREATE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Create_NSCS_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.CREATE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Update() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Update_CREDM_CONTEXT_VALUE() {
        /*
         * final HashMap<String, Serializable> map = new HashMap<String, Serializable>(); map.put(CONTEXT_KEY, CREDM_CONTEXT_VALUE);
         * 
         * Mockito.when(ctxService.getContextData()).thenReturn(map);
         */
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Update_NSCS_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Get() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeReadEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Get_CREDM_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeReadEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Get_NSCS_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeReadEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Delete() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(caEntityAuthorizationHandler).authorizeDeleteEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.DELETE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Delete_CREDM_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeDeleteEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.DELETE);
    }

    @Test
    public void testAuthorizeCAEntityOperations_Delete_NSCS_CONTEXT_VALUE() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeDeleteEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.DELETE);
    }

    @Test
    public void testAuthorizeEntityOperations_Create() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeCreateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
    }

    @Test
    public void testAuthorizeEntityOperations_Create_CREDM_Context() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeCreateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
    }

    @Test
    public void testAuthorizeEntityOperations_Create_NSCS_Context() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeCreateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
    }

    @Test
    public void testAuthorizeEntityOperations_Update() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeEntityOperations_Update_CREDM_Context() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeEntityOperations_Update_NSCS_Context() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeEntityOperations_Get() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeReadEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
    }

    @Test
    public void testAuthorizeEntityOperations_Get_CREDM_Context() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeReadEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
    }

    @Test
    public void testAuthorizeEntityOperations_Get_NSCS_Context() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeReadEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
    }

    @Test
    public void testAuthorizeEntityOperations_Delete() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeDeleteEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.DELETE);
    }

    @Test
    public void testAuthorizeEntityOperations_Delete_NSCS_Context() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeDeleteEntity();
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.DELETE);
    }

    @Test
    public void testAuthorizeOTPOperations_Get_NSCS_CONTEXT() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.READ);
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeOTPOperations_Get() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeUpdateOTP_NSCS_CONTEXT() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeUpdateOTP_CREDM_CONTEXT() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.UPDATE);
    }

    @Test
    public void testAuthorizeUpdateOTP() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        Mockito.doNothing().when(entityAuthorizationHandler).authorizeUpdateEntity();
        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.UPDATE);
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeGetEnrollmentInfo_NSCS_CONTEXT() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.READ);
    }

    @Test
    public void testAuthorizeGetEnrollmentInfo() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeGetEnrollmentInfo();
    }

    @Test
    public void testAuthorize_IsEntityNameAvailable() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(true);
        entityManagementAuthorizationManager.authorizeIsEntityNameAvailable();
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorize_IsEntityNameAvailable_CREDM_CONTEXT() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        entityManagementAuthorizationManager.authorizeIsEntityNameAvailable();
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorize_IsEntityNameAvailable_NSCS_CONTEXT() {
        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        entityManagementAuthorizationManager.authorizeIsEntityNameAvailable();
    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorize_IsOTPValid_CREDM_CONTEXT() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        entityManagementAuthorizationManager.authorizeIsOTPValid();
    }

}
