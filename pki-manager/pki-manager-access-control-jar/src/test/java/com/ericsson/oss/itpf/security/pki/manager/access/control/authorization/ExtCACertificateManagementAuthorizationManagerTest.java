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

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExtCACertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.ExtCACertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACertificateManagementAuthorizationManagerTest {

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private ExtCACertificateManagementAuthorizationHandler externalCAEntityAuthorizationHandler;

    @Mock
    ContextUtility contextUtility;

    @InjectMocks
    ExtCACertificateManagementAuthorizationManager extCACertificateManagementAuthorizationManager;

    @Test
    public void authorizeExternalCAOperationsEXPORTByCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.EXPORT);
    }

    @Test
    public void authorizeExternalCAOperationsEXPORTByAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.EXPORT);
    }

    @Test(expected = SecurityViolationException.class)
    public void authorizeExternalCAOperationsEXPORTByNotAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doThrow(SecurityViolationException.class).when(externalCAEntityAuthorizationHandler).authorizeExportExternalCACeritifcate();
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.EXPORT);
    }

    @Test
    public void authorizeExternalCAOperationsCREATEByCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.CREATE);
    }

    @Test
    public void authorizeExternalCAOperationsCREATEByAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.CREATE);
    }

    @Test(expected = SecurityViolationException.class)
    public void authorizeExternalCAOperationsCREATEByNotAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doThrow(SecurityViolationException.class).when(externalCAEntityAuthorizationHandler).authorizeCreateExternalCA();
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.CREATE);
    }

    @Test
    public void authorizeExternalCAOperationsUPDATEByCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.UPDATE);
    }

    @Test
    public void authorizeExternalCAOperationsUPDATEByAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.UPDATE);
    }

    @Test(expected = SecurityViolationException.class)
    public void authorizeExternalCAOperationsUPDATEByNotAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doThrow(SecurityViolationException.class).when(externalCAEntityAuthorizationHandler).authorizeUpdateExternalCA();
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.UPDATE);
    }

    @Test
    public void authorizeExternalCAOperationsREADByCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.READ);
    }

    @Test
    public void authorizeExternalCAOperationsREADByAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.READ);
    }

    @Test(expected = SecurityViolationException.class)
    public void authorizeExternalCAOperationsREADByNotAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doThrow(SecurityViolationException.class).when(externalCAEntityAuthorizationHandler).authorizeGetExternalCA();
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.READ);
    }

    @Test
    public void authorizeExternalCAOperationsDELETEByCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.DELETE);
    }

    @Test
    public void authorizeExternalCAOperationsDELETEyAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.DELETE);
    }

    @Test(expected = SecurityViolationException.class)
    public void authorizeExternalCAOperationsDELETEByNotAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doThrow(SecurityViolationException.class).when(externalCAEntityAuthorizationHandler).authorizeDeleteExternalCA();
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.DELETE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void authorizeExternalCAOperationsFailed() {
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void authorizeExternalCAOperationsFailedIfIMPORT() {
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.IMPORT);
    }

    @Test
    public void authorizeIsExternalCANameAvailableByCredM() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(true);
        extCACertificateManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
    }

    @Test(expected = SecurityViolationException.class)
    public void authorizeIsExternalCANameAvailableByNotAuthrorizedUser() {
        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        extCACertificateManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
    }

}
