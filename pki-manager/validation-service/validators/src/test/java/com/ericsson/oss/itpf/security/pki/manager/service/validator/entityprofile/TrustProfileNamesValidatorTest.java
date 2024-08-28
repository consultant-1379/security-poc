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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.TrustProfileNamesValidator;

@RunWith(MockitoJUnitRunner.class)
public class TrustProfileNamesValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(TrustProfileNamesValidator.class);

    @InjectMocks
    TrustProfileNamesValidator trustProfileNamesValidator;

    @SuppressWarnings("rawtypes")
    @Mock
    ProfilePersistenceHandler trustProfilePersistenceHandler;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CommonProfileHelper commonProfileHelper;

    private EntityProfile entityProfile = null;
    private TrustProfile trustProfile = new TrustProfile();
    private List<TrustProfile> trustProfiles;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpData.getEntityProfile();

        trustProfile.setName("TrustProfile_1");
        trustProfiles = new ArrayList<TrustProfile>();
        trustProfiles.add(trustProfile);
        entityProfile.setTrustProfiles(trustProfiles);

    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCreateProfileWithValidTrustProfile() {

        when(commonProfileHelper.getPersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(trustProfilePersistenceHandler);
        when(trustProfilePersistenceHandler.getProfile(trustProfile)).thenReturn(trustProfile);

        trustProfileNamesValidator.validate(entityProfile);

    }

    @SuppressWarnings("unchecked")
    @Test(expected = ProfileNotFoundException.class)
    public void testCreateProfileWithInValidTrustProfile() {

        when(commonProfileHelper.getPersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(trustProfilePersistenceHandler);
        when(trustProfilePersistenceHandler.getProfile(trustProfile)).thenReturn(null);

        trustProfileNamesValidator.validate(entityProfile);

    }

    @Test
    public void testCreateProfileWithEmptyTrustProfile() {
        trustProfiles = new ArrayList<TrustProfile>();
        entityProfile.setTrustProfiles(trustProfiles);

        trustProfileNamesValidator.validate(entityProfile);
    }

}
