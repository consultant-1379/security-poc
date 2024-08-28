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

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.EntityAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class EntityAuthorizationHandlerTest {

    @Mock
    Logger logger;

    @InjectMocks
    EntityAuthorizationHandler entityAuthorizationHandler;

    @Test
    public void testCAentityImportOperations() {
        entityAuthorizationHandler.authorizeImportEntities();
    }
    
    @Test
    public void testCAentityCreateOperations() {
        entityAuthorizationHandler.authorizeCreateEntity();
    }

    @Test
    public void testCAentityReadOperations() {
        entityAuthorizationHandler.authorizeReadEntity();
    }

    @Test
    public void testCAentityUpdateOperations() {
        entityAuthorizationHandler.authorizeUpdateEntity();
    }

    @Test
    public void testCAentityDeleteOperations() {
        entityAuthorizationHandler.authorizeDeleteEntity();
    }

    @Test
    public void testEntityCreateOperations() {
        entityAuthorizationHandler.authorizeCreateEntity();
    }

    @Test
    public void testEntityUpdateOperations() {
        entityAuthorizationHandler.authorizeUpdateEntity();
    }

    @Test
    public void testEntityDeleteOperations() {
        entityAuthorizationHandler.authorizeDeleteEntity();
    }

    @Test
    public void testEntityReadOperations() {
        entityAuthorizationHandler.authorizeReadEntity();
    }
}
