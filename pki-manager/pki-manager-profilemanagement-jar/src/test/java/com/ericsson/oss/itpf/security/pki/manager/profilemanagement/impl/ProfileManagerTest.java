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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.persistence.handler.entity.FilteredProfilesFetchHandler;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.validator.BasicValidator;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagerTest {

    @Mock
    Logger logger;

    @InjectMocks
    ProfileManager profileManager;

    @Mock
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @SuppressWarnings("rawtypes")
    @Mock
    ProfilePersistenceHandler profilePersistenceHandler;

    @Mock
    EntityCategory entityCategory;

    @Mock
    BasicValidator profileValidator;

    @Mock
    FilteredProfilesFetchHandler filteredProfilesFetchHandler;

    Profiles profiles = new Profiles();
    TrustProfile trustProfile;
    CertificateProfile certificateProfile;
    EntityProfile entityProfile;
    List<TrustProfile> trustProfileList = new ArrayList<TrustProfile>();

    @Before
    public void setUpData() throws DatatypeConfigurationException {

        trustProfile = new TrustProfileSetUpData().getTrustProfile();
        certificateProfile = new CertificateProfileSetUpData().getCertificateProfile();
        entityProfile = new EntityProfileSetUpData().getEntityProfile();
        trustProfileList.add(trustProfile);
        profiles.setTrustProfiles(trustProfileList);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfiles_All() {

        final Profiles trustProfiles = new Profiles();
        trustProfiles.setTrustProfiles(profiles.getTrustProfiles());

        final Profiles entityProfiles = new Profiles();
        entityProfiles.setEntityProfiles(profiles.getEntityProfiles());

        final Profiles certificateProfiles = new Profiles();
        certificateProfiles.setCertificateProfiles(profiles.getCertificateProfiles());

        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);
        profileTypes.add(ProfileType.TRUST_PROFILE);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);

        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(trustProfiles);
        when(profilePersistenceHandler.getProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfiles);
        when(profilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfiles);

        final Profiles profiles_all = profileManager.getProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        Assert.assertSame(profiles.getTrustProfiles(), profiles_all.getTrustProfiles());
        Assert.assertSame(profiles.getEntityProfiles(), profiles_all.getEntityProfiles());
        Assert.assertSame(profiles.getCertificateProfiles(), profiles_all.getCertificateProfiles());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfiles_TwoArgument() {

        final Profiles trustProfiles = new Profiles();
        trustProfiles.setTrustProfiles(profiles.getTrustProfiles());

        final Profiles entityProfiles = new Profiles();
        entityProfiles.setEntityProfiles(profiles.getEntityProfiles());

        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.ENTITY_PROFILE);
        profileTypes.add(ProfileType.TRUST_PROFILE);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);

        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(trustProfiles);
        when(profilePersistenceHandler.getProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfiles);

        final Profiles profiles_all = profileManager.getProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        Assert.assertSame(profiles.getTrustProfiles(), profiles_all.getTrustProfiles());
        Assert.assertSame(profiles.getEntityProfiles(), profiles_all.getEntityProfiles());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfiles_OneArgument() {

        final Profiles trustProfiles = new Profiles();
        trustProfiles.setTrustProfiles(profiles.getTrustProfiles());
        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.TRUST_PROFILE);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(trustProfiles);

        final Profiles profiles_all = profileManager.getProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        Assert.assertSame(profiles.getTrustProfiles(), profiles_all.getTrustProfiles());

    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIsNameAvailable() {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.isNameAvailable("name")).thenReturn(true);
        Assert.assertTrue(profileManager.isNameAvailable("name", ProfileType.ENTITY_PROFILE));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfilesForTRUST_PROFILE() throws DatatypeConfigurationException {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        Assert.assertEquals(profileManager.getProfiles(ProfileType.TRUST_PROFILE), profiles);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfilesForENTITY_PROFILE() throws DatatypeConfigurationException {

        final Profiles profiles = new Profiles();
        final List<EntityProfile> entityProfileList = new ArrayList<EntityProfile>();
        final EntityProfile entityProfile = new EntityProfileSetUpData().getEntityProfile();
        entityProfileList.add(entityProfile);
        profiles.setEntityProfiles(entityProfileList);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(profiles);
        Assert.assertEquals(profileManager.getProfiles(ProfileType.ENTITY_PROFILE), profiles);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfilesForCERTIFICATE_PROFILE() throws DatatypeConfigurationException {

        final Profiles profiles = new Profiles();
        final List<CertificateProfile> certificateProfileList = new ArrayList<CertificateProfile>();
        final CertificateProfile certificateProfile = new CertificateProfileSetUpData().getCertificateProfile();
        certificateProfileList.add(certificateProfile);
        profiles.setCertificateProfiles(certificateProfileList);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        Assert.assertEquals(profileManager.getProfiles(ProfileType.CERTIFICATE_PROFILE), profiles);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateProfilesForTrustProfile() {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        when(profilePersistenceHandler.updateProfile(profiles.getTrustProfiles().get(0))).thenReturn(trustProfile);
        profileManager.updateProfiles(profiles);
        verify(logger).debug("Profiles updated in bulk");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateProfilesForEntityProfile() throws DatatypeConfigurationException {
        final Profiles profiles = new Profiles();
        final List<EntityProfile> entityProfileList = new ArrayList<EntityProfile>();
        final EntityProfile entityProfile = new EntityProfileSetUpData().getEntityProfile();
        entityProfileList.add(entityProfile);
        profiles.setEntityProfiles(entityProfileList);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(profiles);
        when(profilePersistenceHandler.updateProfile(profiles.getEntityProfiles().get(0))).thenReturn(entityProfile);
        profileManager.updateProfiles(profiles);
        verify(logger).debug("Profiles updated in bulk");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateProfilesForCertificateProfile() throws DatatypeConfigurationException {
        final Profiles profiles = new Profiles();
        final List<CertificateProfile> certificateProfileList = new ArrayList<CertificateProfile>();
        final CertificateProfile certificateProfile = new CertificateProfileSetUpData().getCertificateProfile();
        certificateProfileList.add(certificateProfile);
        profiles.setCertificateProfiles(certificateProfileList);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        when(profilePersistenceHandler.updateProfile(profiles.getCertificateProfiles().get(0))).thenReturn(certificateProfile);
        profileManager.updateProfiles(profiles);
        verify(logger).debug("Profiles updated in bulk");
    }

    @Test
    public void testUpdateProfilesWhenAllProfileNull() {
        profiles.setTrustProfiles(null);
        profiles.setCertificateProfiles(null);
        profiles.setEntityProfiles(null);
        profileManager.updateProfiles(profiles);
        verify(logger).debug("Profiles updated in bulk");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDeleteProfilesForTrustProfile() throws DatatypeConfigurationException {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        profileManager.deleteProfiles(profiles);
        verify(logger).debug("Profiles deleted in bulk");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDeleteProfilesForEntityProfile() throws DatatypeConfigurationException {
        final Profiles profiles = new Profiles();
        final List<EntityProfile> entityProfileList = new ArrayList<EntityProfile>();
        final EntityProfile entityProfile = new EntityProfileSetUpData().getEntityProfile();
        entityProfileList.add(entityProfile);
        profiles.setEntityProfiles(entityProfileList);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        profileManager.deleteProfiles(profiles);
        verify(logger).debug("Profiles deleted in bulk");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDeleteProfilesForCertificateProfile() throws DatatypeConfigurationException {
        final Profiles profiles = new Profiles();
        final List<CertificateProfile> certificateProfileList = new ArrayList<CertificateProfile>();
        final CertificateProfile certificateProfile = new CertificateProfileSetUpData().getCertificateProfile();
        certificateProfileList.add(certificateProfile);
        profiles.setCertificateProfiles(certificateProfileList);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        profileManager.deleteProfiles(profiles);
        verify(logger).debug("Profiles deleted in bulk");
    }

    @Test
    public void testDeleteProfilesWhenAllProfileNull() throws DatatypeConfigurationException {
        profiles.setCertificateProfiles(null);
        profiles.setEntityProfiles(null);
        profiles.setTrustProfiles(null);
        profileManager.deleteProfiles(profiles);
        verify(logger).debug("Profiles deleted in bulk");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCreateProfile() {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        when(profilePersistenceHandler.createProfile(trustProfile)).thenReturn(trustProfile);

        Assert.assertEquals(profileManager.createProfile(trustProfile), trustProfile);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetProfile() {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        when(profilePersistenceHandler.getProfile(trustProfile)).thenReturn(trustProfile);

        Assert.assertEquals(profileManager.getProfile(trustProfile), trustProfile);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetEntityProfilesByCategory() throws DatatypeConfigurationException {
        final List<EntityProfile> entityProfileList = new ArrayList<EntityProfile>();
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getEntityProfilesByCategory(entityCategory)).thenReturn(entityProfileList);

        Assert.assertEquals(profileManager.getEntityProfilesByCategory(entityCategory), entityProfileList);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetActiveProfilesForTrustProfile() {
        final ProfileType[] profileTypes = { ProfileType.TRUST_PROFILE };
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getActiveProfiles(ProfileType.TRUST_PROFILE, true)).thenReturn(profiles);

        Assert.assertEquals(profileManager.getActiveProfiles(profileTypes, true), profiles);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetActiveProfilesForEntityProfile() throws DatatypeConfigurationException {
        final Profiles profiles = new Profiles();
        final List<EntityProfile> entityProfileList = new ArrayList<EntityProfile>();
        final EntityProfile entityProfile = new EntityProfileSetUpData().getEntityProfile();
        entityProfileList.add(entityProfile);
        profiles.setEntityProfiles(entityProfileList);
        final ProfileType[] profileTypes = { ProfileType.ENTITY_PROFILE };

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getActiveProfiles(ProfileType.ENTITY_PROFILE, true)).thenReturn(profiles);

        Assert.assertEquals(profileManager.getActiveProfiles(profileTypes, true), profiles);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetActiveProfilesForCertificateProfile() throws DatatypeConfigurationException {
        final Profiles profiles = new Profiles();
        final List<CertificateProfile> certificateProfileList = new ArrayList<CertificateProfile>();
        final CertificateProfile certificateProfile = new CertificateProfileSetUpData().getCertificateProfile();
        certificateProfileList.add(certificateProfile);
        profiles.setCertificateProfiles(certificateProfileList);
        final ProfileType[] profileTypes = { ProfileType.CERTIFICATE_PROFILE };

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getActiveProfiles(ProfileType.CERTIFICATE_PROFILE, true)).thenReturn(profiles);

        Assert.assertEquals(profileManager.getActiveProfiles(profileTypes, true), profiles);
    }

    @Test
    public void testGetProfilesCountByFilterWithEmptyType() {
        final ProfilesFilter profilesFilter = new ProfilesFilter();

        profilesFilter.setType(null);
        profilesFilter.setName("");
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE).getProfilesCountByFilter(profilesFilter)).thenReturn(10);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE).getProfilesCountByFilter(profilesFilter)).thenReturn(10);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE).getProfilesCountByFilter(profilesFilter)).thenReturn(10);
        final int count = profileManager.getProfilesCountByFilter(profilesFilter);
        assertEquals(30, count);
    }

    @Test
    public void testGetProfilesCountByFilter() {
        final ProfilesFilter profilesFilter = new ProfilesFilter();
        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);
        profileTypes.add(ProfileType.TRUST_PROFILE);

        profilesFilter.setType(profileTypes);
        profilesFilter.setName("");
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);

        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE).getProfilesCountByFilter(profilesFilter)).thenReturn(10);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE).getProfilesCountByFilter(profilesFilter)).thenReturn(10);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE).getProfilesCountByFilter(profilesFilter)).thenReturn(10);
        final int count = profileManager.getProfilesCountByFilter(profilesFilter);
        assertEquals(30, count);
    }

    @Test
    public void testGetProfileDetails() {
        final ProfilesFilter profilesFilter = new ProfilesFilter();
        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profilesFilter.setType(profileTypes);
        profilesFilter.setName("");

        profileManager.getProfileDetails(profilesFilter);
        Mockito.verify(filteredProfilesFetchHandler).getProfileDetails(profilesFilter);
    }

    @Test
    public void testGetModifiableStatus() {
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfileModifiableStatus(certificateProfile)).thenReturn(true);
        Assert.assertEquals(profileManager.getModifiableStatus(certificateProfile), true);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfileModifiableStatus(entityProfile)).thenReturn(true);
        Assert.assertEquals(profileManager.getModifiableStatus(entityProfile), true);
        when(profilePersistenceHandlerFactory.getProfilePersistenceHandler(ProfileType.TRUST_PROFILE)).thenReturn(profilePersistenceHandler);
        when(profilePersistenceHandler.getProfileModifiableStatus(trustProfile)).thenReturn(true);
        Assert.assertEquals(profileManager.getModifiableStatus(trustProfile), true);
    }
}
