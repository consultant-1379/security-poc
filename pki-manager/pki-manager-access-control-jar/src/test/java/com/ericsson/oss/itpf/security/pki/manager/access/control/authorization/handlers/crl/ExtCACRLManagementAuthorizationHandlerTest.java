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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl.ExtCACRLManagementAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACRLManagementAuthorizationHandlerTest {

    @Mock
    Logger logger;

    @InjectMocks
    ExtCACRLManagementAuthorizationHandler externalCACRLEntityAuthorizationHandler;

    @Test
    public void testAuthorizeUpdateExternalCA() {
        externalCACRLEntityAuthorizationHandler.authorizeUpdateExternalCA();
    }

    @Test
    public void testAuthorizeGetExternalCRLInfo() {
        externalCACRLEntityAuthorizationHandler.authorizeGetExternalCRLInfo();
    }

    @Test
    public void testAuthorizeDeleteExternalCRLInfo() {
        externalCACRLEntityAuthorizationHandler.authorizeDeleteExternalCRLInfo();
    }
}
