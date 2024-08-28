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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.validator.BasicValidator;

@RunWith(MockitoJUnitRunner.class)
public class TrustProfileManagerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(ProfileManager.class);

    @InjectMocks
    private ProfileManager trustProfileManager;

    @Mock
    private BasicValidator profileValidator;

    @Mock
    private ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    private ProfilePersistenceHandler profilePersistencehandler;

    private TrustProfile trustProfile;

    private List<TrustProfile> trustProfileList;

    private Profiles profiles;

    /**
     * Method to fill test data into TrustProfile
     */
    @Before
    public void setup() {
        profiles = new Profiles();
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        trustProfileList = trustProfileSetUpData.getTrustProfileList();
        trustProfile = trustProfileList.get(0);
        profiles.setTrustProfiles(trustProfileList);

    }

    /**
     * Method to test createProfile in positive scenario
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testCreateProfile() {

        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistencehandler);
        when(profilePersistencehandler.createProfile(trustProfile)).thenReturn(trustProfile);
        assertEquals(trustProfileManager.createProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test getProfiles in positive scenario
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfiles() {

        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistencehandler);
        when(profilePersistencehandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        assertEquals(trustProfileManager.getProfiles(ProfileType.TRUST_PROFILE), profiles);
    }

    /**
     * Method to test getProfile in positive scenario
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfile() {

        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistencehandler);
        when(profilePersistencehandler.getProfile(trustProfile)).thenReturn(trustProfile);
        assertEquals(trustProfileManager.getProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test updateProfile in positive scenario
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateProfile() {

        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistencehandler);
        when(profilePersistencehandler.updateProfile(trustProfile)).thenReturn(trustProfile);
        assertEquals(trustProfileManager.updateProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test deleteProfile in positive scenario
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testDeletetProfile() {

        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistencehandler);

        trustProfileManager.deleteProfile(trustProfile);

    }

    /**
     * Method to test isNameAvailable in positive scenario
     */
    @Test
    public void testIsNameAvailable() {

        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistencehandler);
        when(profilePersistencehandler.isNameAvailable("TestProfile")).thenReturn(true);
        assertTrue(trustProfileManager.isNameAvailable("TestProfile", ProfileType.TRUST_PROFILE));
    }
}
