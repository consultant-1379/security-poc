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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.EntityCertificateManagementAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertificateManagementAuthorizationHandlerTest {

    @InjectMocks
    EntityCertificateManagementAuthorizationHandler entityCertificateManagemntAuthorizationHandler;

    @Mock
    Logger logger;

    @Test
    public void testAuthorizeGenerateCertificate() {
        entityCertificateManagemntAuthorizationHandler.authorizeGenerateCertificate();
    }

    @Test
    public void testAuthorizeGetCertificate() {
        entityCertificateManagemntAuthorizationHandler.authorizeGetCertificate();
    }

    @Test
    public void testAuthorizeUpdateCertificate() {
        entityCertificateManagemntAuthorizationHandler.authorizeUpdateCertificate();
    }

}
