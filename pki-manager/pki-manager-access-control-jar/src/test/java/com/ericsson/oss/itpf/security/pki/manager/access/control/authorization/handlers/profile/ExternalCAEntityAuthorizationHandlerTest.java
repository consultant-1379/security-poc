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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

@RunWith(MockitoJUnitRunner.class)
public class ExternalCAEntityAuthorizationHandlerTest {

    @Mock
    Logger logger;

    @InjectMocks
    ExternalCAAuthorizationHandler externalCAEntityAuthorizationHandler;

    @Test
    public void testAuthorizeExportExternalCACeritifcate() {
        externalCAEntityAuthorizationHandler.authorizeExportExternalCACeritifcate();
    }

    @Test
    public void testAuthorizeCreateExternalCA() {
        externalCAEntityAuthorizationHandler.authorizeCreateExternalCA();
    }

    @Test
    public void testAuthorizeGetExternalCA() {
        externalCAEntityAuthorizationHandler.authorizeGetExternalCA();
    }

    @Test
    public void testAuthorizeUpdateExternalCA() {
        externalCAEntityAuthorizationHandler.authorizeUpdateExternalCA();
    }

    @Test
    public void testAuthorizeDeleteExternalCA() {
        externalCAEntityAuthorizationHandler.authorizeDeleteExternalCA();
    }
}
