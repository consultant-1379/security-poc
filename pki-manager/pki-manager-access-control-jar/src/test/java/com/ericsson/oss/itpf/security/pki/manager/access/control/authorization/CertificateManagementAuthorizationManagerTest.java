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

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.CACertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.EntityCertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementAuthorizationManagerTest {

    @InjectMocks
    CertificateManagementAuthorizationManager certificateManagementAuthorization;

    @Mock
    CACertificateManagementAuthorizationHandler caCertificateManagementAuthorizationHandler;

    @Mock
    EntityCertificateManagementAuthorizationHandler entityCertificateManagementAuthorizationHandler;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    ContextUtility contextUtility;

    @Test
    public void testAuthorizeGenerateCetificate_CAEntity() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);
        Mockito.doNothing().when(caCertificateManagementAuthorizationHandler).authorizeGenerateCertificate();

        certificateManagementAuthorization.authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.CA_ENTITY);

    }

    @Test
    public void testAuthorizeGenerateCetificate_Entity() {

        Mockito.when(contextUtility.isCredMOperation()).thenReturn(false);

        Mockito.doNothing().when(entityCertificateManagementAuthorizationHandler).authorizeGenerateCertificate();
        certificateManagementAuthorization.authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);

    }

    @Test
    public void testAuthorizeUpdateCertificate_CAEntity() {

        Mockito.doNothing().when(caCertificateManagementAuthorizationHandler).authorizeUpdateCertificate();
        certificateManagementAuthorization.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

    }

    @Test
    public void testAuthorizeUpdateCertificate_Entity() {

        Mockito.doNothing().when(entityCertificateManagementAuthorizationHandler).authorizeUpdateCertificate();
        certificateManagementAuthorization.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);

    }

    @Test
    public void testAuthorizeGetCertificate_CAEntity() {

        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);

        Mockito.doNothing().when(caCertificateManagementAuthorizationHandler).authorizeGetCertificate();
        certificateManagementAuthorization.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

    }

    @Test
    public void testAuthorizeGetCertificate_Entity() {

        Mockito.doNothing().when(caCertificateManagementAuthorizationHandler).authorizeGetCertificate();
        certificateManagementAuthorization.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

    }

    @Test(expected = SecurityViolationException.class)
    public void testAuthorizeGetTrustCertificates() {

        Mockito.when(contextUtility.isNSCSOperation()).thenReturn(false);
        certificateManagementAuthorization.authorizeGetTrustCertificates();

    }

}
