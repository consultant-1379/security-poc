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
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link CertificateProfileManager}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileManagerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(ProfileManager.class);

    @InjectMocks
    private ProfileManager certificateProfileManager;

    @Mock
    private ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    private ProfilePersistenceHandler certificateProfilePersistenceHandler;

    private CertificateProfile certificateProfile;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();

        final CAEntity caEntity = new CAEntity();
        certificateProfile.setIssuer(caEntity);
    }

    /**
     * Method to test createProfile Method in positive scenario.
     */
    @Test
    public void testCreateProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.createProfile(certificateProfile)).thenReturn(certificateProfile);
        assertEquals(certificateProfileManager.createProfile(certificateProfile), certificateProfile);
    }

    /**
     * Method to test createProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testCreateProfileWithProfileServiceException() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.createProfile(certificateProfile)).thenThrow(new ProfileServiceException());

        certificateProfileManager.createProfile(certificateProfile);
    }

    /**
     * Method to test getProfiles Method in positive scenario.
     */
    @Test
    public void testGetProfiles() {
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        final Profiles profiles = new Profiles();
        profiles.setCertificateProfiles(certificateProfiles);
        certificateProfiles.add(certificateProfile);
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        assertEquals(certificateProfileManager.getProfiles(ProfileType.CERTIFICATE_PROFILE).getCertificateProfiles().get(0).getName(), certificateProfile.getName());
    }

    /**
     * Method to test getProfiles Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfilesWithInternalServiceException() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new ProfileServiceException());

        certificateProfileManager.getProfiles(ProfileType.CERTIFICATE_PROFILE);
    }

    /**
     * Method to test getProfile Method in positive scenario.
     */
    @Test
    public void testGetProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.getProfile(certificateProfile)).thenReturn(certificateProfile);
        assertEquals(certificateProfileManager.getProfile(certificateProfile).getName(), certificateProfile.getName());
    }

    /**
     * Method to test getProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileWithInternalServiceException() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.getProfile(certificateProfile)).thenThrow(new ProfileServiceException());
        certificateProfileManager.getProfile(certificateProfile);
    }

    /**
     * Method to test getProfile Method in negative scenario.
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetProfileWithProfileNotFoundException() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.getProfile(certificateProfile)).thenThrow(new ProfileNotFoundException());
        certificateProfileManager.getProfile(certificateProfile);
    }

    /**
     * Method to test updateProfile Method in positive scenario.
     */
    @Test
    public void testUpdateProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        when(certificateProfilePersistenceHandler.updateProfile(certificateProfile)).thenReturn(certificateProfile);
        assertEquals(certificateProfileManager.updateProfile(certificateProfile).getName(), certificateProfile.getName());
    }

    /**
     * Method to test deleteProfile Method in positive scenario.
     */
    @Test(expected = ProfileInUseException.class)
    public void testDeleteProfile() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        doThrow(new ProfileInUseException()).when(certificateProfilePersistenceHandler).deleteProfile(certificateProfile);
        certificateProfileManager.deleteProfile(certificateProfile);
    }

    /**
     * Method to test isNameAvailable Method in positive scenario.
     */
    @Test
    public void testIsNameAvailable() {
        when(persistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfilePersistenceHandler);
        assertFalse(certificateProfileManager.isNameAvailable("TestCP", ProfileType.CERTIFICATE_PROFILE));
    }
}
