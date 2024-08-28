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

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.CACertificateManagementAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class CACertificateManagementAuthorizationHandlerTest {

    @InjectMocks
    CACertificateManagementAuthorizationHandler caCertificateManagementAuthorizationHandler;

    @Mock
    Logger logger;

    @Test
    public void testAuthorizeGenerateCertificate() {
        caCertificateManagementAuthorizationHandler.authorizeGenerateCertificate();
    }

    @Test
    public void testAuthorizeGetCertificate() {
        caCertificateManagementAuthorizationHandler.authorizeGetCertificate();
    }

    @Test
    public void testAuthorizeUpdateCertificate() {
        caCertificateManagementAuthorizationHandler.authorizeUpdateCertificate();
    }
}
