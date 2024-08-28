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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.math.BigInteger;
import java.util.*;

import javax.persistence.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.ProfileModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;

@RunWith(MockitoJUnitRunner.class)
public class TrustProfilePersistenceHandlerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(AbstractProfilePersistenceHandler.class);

    @InjectMocks
    private TrustProfilePersistenceHandler<TrustProfile> trustProfilePersistenceHandler;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private ProfileModelMapperFactory profileModelMapperFactory;

    @Mock
    private ModelMapper modelMapper;

    private TrustProfileData trustProfileData;
    private List<TrustProfileData> trustProfileDataList;
    private TrustProfile trustProfile;
    private List<TrustProfile> trustProfileList;
    private Profiles profiles;
    private List<EntityProfileData> entityProfileDatas;

    private final static String PROFILE_NAME = "TestTP";
    private final static BigInteger ID = new BigInteger("123765676");

    private final static String queryForFetchActiveTrustProfiles = "select id,name from trustprofile where is_active=true";

    /**
     * Method to fill test data into TrustProfile
     */
    @Before
    public void setup() {
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();

        trustProfileDataList = trustProfileSetUpData.getTrustProfileDataList();
        trustProfileData = trustProfileDataList.get(0);
        trustProfileList = trustProfileSetUpData.getTrustProfileList();
        trustProfile = trustProfileList.get(0);

        profiles = new Profiles();
        profiles.setTrustProfiles(trustProfileList);
        entityProfileDatas = trustProfileSetUpData.getEntityProfileDatas();

    }

    /**
     * Method to test getProfiles in positive scenario
     */
    @Test
    public void testGetProfiles() {
        when(persistenceManager.getAllEntityItems(TrustProfileData.class)).thenReturn(trustProfileDataList);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);
        final Profiles trustProfiles = trustProfilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE);
        assertEquals(trustProfiles, profiles);
    }

    /**
     * Method to test getProfiles in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfilesPersistenceException() {
        when(persistenceManager.getAllEntityItems(TrustProfileData.class)).thenThrow(new PersistenceException());
        trustProfilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE);

    }

    /**
     * Method to test getProfiles in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfilesWithInternalServiceException() {
        when(persistenceManager.getAllEntityItems(TrustProfileData.class)).thenThrow(new ProfileServiceException());
        trustProfilePersistenceHandler.getProfiles(ProfileType.TRUST_PROFILE);
    }

    /**
     * Method to test getProfile in positive scenario
     */
    @Test
    public void testGetProfile() {
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);
        assertEquals(trustProfilePersistenceHandler.getProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test getProfile in negative scenario
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testGetProfileNull() {
        trustProfile.setId(0);
        trustProfile.setName(null);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);
        assertEquals(trustProfilePersistenceHandler.getProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test getProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfilePersistenceException() {
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new PersistenceException());

        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileException() {
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new ProfileServiceException());

        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfile in negative scenario
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetProfileProfileNotFound() {
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(null);
        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfileById in positive scenario
     */
    @Test
    public void testGetProfileById() {
        trustProfile.setName(null);
        when(persistenceManager.findEntity(TrustProfileData.class, trustProfile.getId())).thenReturn(trustProfileData);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);
        assertEquals(trustProfilePersistenceHandler.getProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test getProfileById in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileByIdPersistenceException() {
        trustProfile.setName(null);
        when(persistenceManager.findEntity(TrustProfileData.class, trustProfile.getId())).thenThrow(new PersistenceException());

        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfileById in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileByIdException() {
        trustProfile.setName(null);
        when(persistenceManager.findEntity(TrustProfileData.class, trustProfile.getId())).thenThrow(new ProfileServiceException());

        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfileById in negative scenario
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetProfileByIdProfileNotFound() {
        trustProfile.setName(null);
        when(persistenceManager.findEntity(TrustProfileData.class, trustProfile.getId())).thenReturn(null);
        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfileByName in positive scenario
     */
    @Test
    public void testGetProfileByName() {
        trustProfile.setId(0);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);
        assertEquals(trustProfilePersistenceHandler.getProfile(trustProfile), trustProfile);
    }

    /**
     * Method to test getProfileByName in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileByNamePersistenceException() {
        trustProfile.setId(0);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new PersistenceException());

        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfileByName in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileByNameException() {
        trustProfile.setId(0);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new ProfileServiceException());

        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test getProfileByName in negative scenario
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetProfileByNameProfileNotFound() {
        trustProfile.setId(0);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(null);
        trustProfilePersistenceHandler.getProfile(trustProfile);
    }

    /**
     * Method to test deleteProfile in positive scenario
     */
    @Test
    public void testDeleteProfile() {
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);

        trustProfilePersistenceHandler.deleteProfile(trustProfile);

    }

    /**
     * Method to test deleteProfile in negative scenario
     */
    @Test(expected = ProfileInUseException.class)
    public void testDeleteProfileWithEntityProfile() {
        final Map<String, Object> hmAttributes = new HashMap<String, Object>();
        hmAttributes.put("trust_profile_id", trustProfileData.getId());
        hmAttributes.put("is_active", true);
        final String entityProfileQuery = "select e from EntityProfileData e join e.trustProfileDatas t where e.active in(:is_active) and t.id=:trust_profile_id";
        ;

        when(persistenceManager.findEntitiesByAttributes(EntityProfileData.class, entityProfileQuery, hmAttributes)).thenReturn(entityProfileDatas);
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);

        trustProfilePersistenceHandler.deleteProfile(trustProfile);

    }

    /**
     * Method to test deleteProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testDeleteProfileWithInternalServiceException() {
        when(persistenceManager.findEntityByIdAndName(TrustProfileData.class, trustProfile.getId(), trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        doThrow(new TransactionRequiredException()).when(persistenceManager).deleteEntity(trustProfileData);
        trustProfilePersistenceHandler.deleteProfile(trustProfile);

    }

    /**
     * Method to test createProfile in positive scenario
     */
    @Test
    public void testCreateProfile() {
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);

        assertEquals(trustProfile, trustProfilePersistenceHandler.createProfile(trustProfile));
    }

    /**
     * Method to test createProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testCreateProfilePersistenceException() {

        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new TransactionRequiredException());

        trustProfilePersistenceHandler.createProfile(trustProfile);
    }

    /**
     * Method to test createProfile in negative scenario
     */
    @Test(expected = ProfileAlreadyExistsException.class)
    public void testCreateProfileEntityExistsException() {
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new EntityExistsException());

        trustProfilePersistenceHandler.createProfile(trustProfile);
    }

    /**
     * Method to test createProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testCreateProfileException() {
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new ProfileServiceException());

        trustProfilePersistenceHandler.createProfile(trustProfile);
    }

    /**
     * Method to test updateProfile in positive scenario
     */
    @Test
    public void testUpdateProfile() {

        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        when(modelMapper.toAPIFromModel(trustProfileData)).thenReturn(trustProfile);

        assertEquals(trustProfile, trustProfilePersistenceHandler.updateProfile(trustProfile));
    }

    /**
     * Method to test updateProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testUpdateProfilePersistenceException() {

        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new TransactionRequiredException());

        trustProfilePersistenceHandler.updateProfile(trustProfile);
    }

    /**
     * Method to test updateProfile in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testUpdateProfileException() {

        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(trustProfile)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), TrustProfileSetUpData.NAME_PATH)).thenThrow(new ProfileServiceException());

        trustProfilePersistenceHandler.updateProfile(trustProfile);
    }

    /**
     * Method to test isNameAvailable in positive scenario
     */
    @Test
    public void testIsNameAvailableFalse() {
        when(persistenceManager.findEntityByName(TrustProfileData.class, "trustprofile", TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        assertFalse(trustProfilePersistenceHandler.isNameAvailable("trustprofile"));
    }

    /**
     * Method to test isNameAvailable in negative scenario
     */
    @Test
    public void testIsNameAvailableTrue() {
        when(persistenceManager.findEntityByName(TrustProfileData.class, "trustprofile", TrustProfileSetUpData.NAME_PATH)).thenReturn(null);
        assertTrue(trustProfilePersistenceHandler.isNameAvailable("trustprofile"));
    }

    /**
     * Method to test get trust profiles without types in a positive scenario.
     */

    @Test
    public void testgetProfilesCountByFilterwithoutTypes() {

        final ProfilesFilter profilesFilter = getProfilesFilter();
        profilesFilter.setType(null);

        Mockito.when(persistenceManager.getEntitiesCount(TrustProfileData.class)).thenReturn((long) 1);

        final int count = trustProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(1, count);
    }

    /**
     * Method to get trust profiles with types in a positive scenario
     * 
     */
    @Test
    public void testgetProfilesCountByFilter() {

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final Map<String, Object> attributes = new HashMap<String, Object>();

        attributes.put("trustProfileName", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        Mockito.when(persistenceManager.findEntitiesCountByAttributes("select * from test", attributes)).thenReturn((long) 1);

        final int count = trustProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(0, count);
    }

    /**
     * this method tests the get active profiles in positive scenario
     */
    @Test
    public void testgetActiveProfiles() {
        final ProfileType profileType = ProfileType.TRUST_PROFILE;
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

        Mockito.when(trustProfilePersistenceHandler.getActiveProfiles(TrustProfileData.class, profileType)).thenReturn(trustProfiles);
        final Profiles profiles = trustProfilePersistenceHandler.getActiveProfiles(profileType, true);

        Assert.assertEquals(trustProfiles, profiles.getTrustProfiles());
    }

    /**
     * this method tests the get active profiles in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetActiveProfiles_ProfileServiceException() {
        final ProfileType profileType = ProfileType.TRUST_PROFILE;
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

        Mockito.when(trustProfilePersistenceHandler.getActiveProfiles(TrustProfileData.class, profileType)).thenThrow(new PersistenceException());
        final Profiles profiles = trustProfilePersistenceHandler.getActiveProfiles(profileType, true);

        Assert.assertEquals(trustProfiles, profiles.getTrustProfiles());
    }

    /**
     * this method tests the get active profiles in positive scenario
     */
    @Test
    public void testgetForActiveProfilesIdAndName() {
        final ProfileType profileType = ProfileType.TRUST_PROFILE;
        final Object[] obj = new Object[] { ID, PROFILE_NAME };

        final List<Object[]> entities = new ArrayList<Object[]>();
        entities.add(obj);

        Mockito.when(trustProfilePersistenceHandler.fetchActiveProfilesIdAndName(queryForFetchActiveTrustProfiles)).thenReturn(entities);

        final Profiles profiles = trustProfilePersistenceHandler.getActiveProfiles(profileType, false);
        final List<TrustProfile> trustProfiles = profiles.getTrustProfiles();

        Assert.assertEquals(123765676, trustProfiles.get(0).getId());
        Assert.assertEquals(PROFILE_NAME, trustProfiles.get(0).getName());
    }

    /**
     * this method tests the get active profiles in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetForActiveProfilesIdAndName_ProfileServiceException() {
        final ProfileType profileType = ProfileType.TRUST_PROFILE;
        final Object[] obj = new Object[] { ID, PROFILE_NAME };

        final List<Object[]> entities = new ArrayList<Object[]>();
        entities.add(obj);

        Mockito.when(trustProfilePersistenceHandler.fetchActiveProfilesIdAndName(queryForFetchActiveTrustProfiles)).thenThrow(new PersistenceException());

        final Profiles profiles = trustProfilePersistenceHandler.getActiveProfiles(profileType, false);
        final List<TrustProfile> trustProfiles = profiles.getTrustProfiles();

        Assert.assertEquals(123765676, trustProfiles.get(0).getId());
        Assert.assertEquals(PROFILE_NAME, trustProfiles.get(0).getName());
    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfilesFilter getProfilesFilter() {

        final ProfilesFilter profilesFilter = new ProfilesFilter();

        profilesFilter.setLimit(10);
        profilesFilter.setOffset(1);
        profilesFilter.setName("Test%");

        final com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter status = new com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter();
        status.setActive(true);
        status.setInactive(true);

        profilesFilter.setStatus(status);

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.TRUST_PROFILE);

        profilesFilter.setType(types);

        return profilesFilter;
    }
}
