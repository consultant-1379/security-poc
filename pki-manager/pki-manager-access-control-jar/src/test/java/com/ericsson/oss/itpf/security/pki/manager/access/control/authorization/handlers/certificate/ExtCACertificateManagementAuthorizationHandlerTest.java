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

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.ExtCACertificateManagementAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACertificateManagementAuthorizationHandlerTest {

    @Mock
    private Logger logger;

    @InjectMocks
    ExtCACertificateManagementAuthorizationHandler extCACertificateManagementAuthorizationHandler;

    @Test
    public void authorizeExportExternalCACeritifcate() {
        extCACertificateManagementAuthorizationHandler.authorizeExportExternalCACeritifcate();
    }

    @Test
    public void authorizeCreateExternalCA() {
        extCACertificateManagementAuthorizationHandler.authorizeCreateExternalCA();
    }

    @Test
    public void authorizeGetExternalCA() {
        extCACertificateManagementAuthorizationHandler.authorizeGetExternalCA();
    }

    @Test
    public void authorizeUpdateExternalCA() {
        extCACertificateManagementAuthorizationHandler.authorizeUpdateExternalCA();
    }

    @Test
    public void authorizeDeleteExternalCA() {
        extCACertificateManagementAuthorizationHandler.authorizeDeleteExternalCA();
    }
}
