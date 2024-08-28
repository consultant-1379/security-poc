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

import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.ProfileAuthorizationHandler;

@RunWith(MockitoJUnitRunner.class)
public class ProfileAuthorizationHandlerTest {

    @Mock
    Logger logger;

    @InjectMocks
    ProfileAuthorizationHandler profileAuthorizationHandler;

    @Test
    public void testImportProfiles() {
        profileAuthorizationHandler.authorizeImportProfiles();
    }

    @Test
    public void testExportProfiles() {
        profileAuthorizationHandler.authorizeExportProfiles();
    }

    @Test
    public void testGetProfile() {
        profileAuthorizationHandler.authorizeGetProfile();
    }

    @Test
    public void testUpdateProfile() {
        profileAuthorizationHandler.authorizeUpdateProfile();
    }

    @Test
    public void testCreateProfile() {
        profileAuthorizationHandler.authorizeCreateProfile();
    }

    @Test
    public void testDeleteProfile() {
        profileAuthorizationHandler.authorizeDeleteProfile();
    }
}
