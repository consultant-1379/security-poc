/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

@RunWith(MockitoJUnitRunner.class)
public class ProfilePersistenceHandlerFactoryTest {

    @InjectMocks
    private ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    private ProfilePersistenceHandler<TrustProfile> trustProfilePersistenceHandler;

    @Mock
    private ProfilePersistenceHandler<CertificateProfile> certificateProfilePersistenceHandler;

    @Mock
    private ProfilePersistenceHandler<EntityProfile> entityProfilePersistenceHandler;

    @Test
    public void testGetProfilePersistenceHandler_TRUST_PROFILE_TrustProfileValidator() {
        assertEquals(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE), trustProfilePersistenceHandler);
    }

    @Test
    public void testGetProfilePersistenceHandler_CERTIFICATE_PROFILE_CertificateProfileValidator() {
        assertEquals(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE), certificateProfilePersistenceHandler);
    }

    @Test
    public void testGetProfilePersistenceHandler_ENTITY_PROFILE_EntityProfileValidator() {
        assertEquals(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE), entityProfilePersistenceHandler);
    }

}
