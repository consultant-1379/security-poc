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

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.CAEntityAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityAuthorizationHandlerTest {

    @Mock
    Logger logger;

    @InjectMocks
    CAEntityAuthorizationHandler caEntityAuthorizationHandler;

    @Test
    public void testCAentityImportOperations() {
        caEntityAuthorizationHandler.authorizeImportEntities();
    }
    
    @Test
    public void testCAentityCreateOperations() {
        caEntityAuthorizationHandler.authorizeCreateEntity();
    }

    @Test
    public void testCAentityReadOperations() {
        caEntityAuthorizationHandler.authorizeReadEntity();
    }

    @Test
    public void testCAentityUpdateOperations() {
        caEntityAuthorizationHandler.authorizeUpdateEntity();
    }

    @Test
    public void testCAentityDeleteOperations() {
        caEntityAuthorizationHandler.authorizeDeleteEntity();
    }

    @Test
    public void testEntityCreateOperations() {
        caEntityAuthorizationHandler.authorizeCreateEntity();
    }

    @Test
    public void testEntityUpdateOperations() {
        caEntityAuthorizationHandler.authorizeUpdateEntity();
    }

    @Test
    public void testEntityDeleteOperations() {
        caEntityAuthorizationHandler.authorizeDeleteEntity();
    }

    @Test
    public void testEntityReadOperations() {
        caEntityAuthorizationHandler.authorizeReadEntity();
    }
}
