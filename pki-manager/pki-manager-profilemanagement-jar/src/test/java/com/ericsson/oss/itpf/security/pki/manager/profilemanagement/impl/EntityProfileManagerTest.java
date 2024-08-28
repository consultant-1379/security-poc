package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import static org.junit.Assert.assertEquals;
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

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntityProfileSetUpData;


@RunWith(MockitoJUnitRunner.class)
public class EntityProfileManagerTest {
    @Spy
    Logger logger = LoggerFactory.getLogger(ProfileManager.class);

    @InjectMocks
    ProfileManager entityProfileManager;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    ProfilePersistenceHandler entityProfilePersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    EntityProfile entityProfile = null;
    EntityProfileData entityProfileData = null;
    CertificateProfile certificateProfile = null;
    CertificateProfileData certificateProfileData = null;
    TrustProfileData trustProfileData = null;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        entityProfile = entityProfileSetUpData.getEntityProfile();
        entityProfileData = entityProfileSetUpData.getEntityProfileData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();
        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions());
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions()));
        trustProfileData = new TrustProfileData();
        trustProfileData.setName("TrustProfile_1");
    }

    /**
     * Method to test getProfile Method in positive scenario.
     */
    @Test
    public void testGetProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfilePersistenceHandler);
        when(entityProfilePersistenceHandler.getProfile(entityProfile)).thenReturn(entityProfile);
        assertEquals(entityProfileManager.getProfile(entityProfile).getName(), entityProfile.getName());
    }

    /**
     * Method to test getProfiles Method in positive scenario.
     */
    @Test
    public void testGetProfiles() {
        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();
        final Profiles profiles = new Profiles();
        profiles.setEntityProfiles(entityProfiles);
        entityProfiles.add(entityProfile);
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfilePersistenceHandler);
        when(entityProfilePersistenceHandler.getProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(profiles);
        assertEquals(entityProfileManager.getProfiles(ProfileType.ENTITY_PROFILE).getEntityProfiles().get(0).getName(), entityProfile.getName());
    }

    /**
     * Method to test updateProfile Method in positive scenario.
     */
    @Test
    public void testUpdateProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfilePersistenceHandler);
        when(entityProfilePersistenceHandler.updateProfile(entityProfile)).thenReturn(entityProfile);
        assertEquals(entityProfileManager.updateProfile(entityProfile).getName(), entityProfile.getName());
    }

    /**
     * Method to test deleteProfile Method in positive scenario.
     */
    @Test
    public void testDeleteProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfilePersistenceHandler);
        entityProfileManager.deleteProfile(entityProfile);

    }

    /**
     * Method to test isNameAvailable Method in positive scenario.
     */
    @Test
    public void testIsNameAvailable() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfilePersistenceHandler);
        assertEquals(entityProfileManager.isNameAvailable("EntityProfile_1", ProfileType.ENTITY_PROFILE), false);
    }

}
