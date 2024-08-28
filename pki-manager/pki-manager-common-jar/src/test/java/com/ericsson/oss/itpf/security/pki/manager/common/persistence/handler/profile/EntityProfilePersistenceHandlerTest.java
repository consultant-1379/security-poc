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
/**
 * @author tcschsa
 *
 */
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityCategorySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.ProfileModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

@RunWith(MockitoJUnitRunner.class)
public class EntityProfilePersistenceHandlerTest {
    @Spy
    Logger logger = LoggerFactory.getLogger(EntityProfilePersistenceHandler.class);

    @InjectMocks
    private EntityProfilePersistenceHandler<EntityProfile> entityProfilePersistenceHandler;

    @Mock
    private EntityProfileMapper entityProfileMapper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    ModelMapper entityProfile_Mapper;

    @Mock
    private ProfileModelMapperFactory profileModelMapperFactory;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private final static String PROFILE_NAME = "TestEP";
    private final static BigInteger ID = new BigInteger("123765676");

    EntityProfile entityProfile = null;
    EntityProfileData entityProfileData = null;
    EntityCategoryData entityCategoryData = null;

    static private final String caEntityQuery = "select e from CAEntityData e join e.entityProfileData ep where ep.id=:entity_profile_id";
    static private final String entityQuery = "select e from EntityData e join e.entityProfileData ep where ep.id=:entity_profile_id";
    private final static String queryForFetchActiveEntityProfiles = "select id,name from entityprofile where is_active=true";
    private static EntityCategory entityCategory = new EntityCategory();
    private static final Map<String, Object> input = new HashMap<String, Object>();

    @Before
    public void setUp() throws DatatypeConfigurationException {
        final EntityProfileSetUpData entityProfileSetUpToTest = new EntityProfileSetUpData();
        final EntityCategorySetUpData entityCategorySetUpData = new EntityCategorySetUpData();

        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        entityProfileData = entityProfileSetUpToTest.getEntityProfileData();
        entityCategoryData = entityCategorySetUpData.getEntityCategoryData();
        input.put("entityCategoryData", null);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testGetProfile() throws DatatypeConfigurationException {

        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfileMapper);
        when(persistenceManager.findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        when(entityProfileMapper.toAPIFromModel(entityProfileData)).thenReturn(entityProfile);
        final EntityProfile testentityProfile = (EntityProfile) entityProfilePersistenceHandler.getProfile(entityProfile);

        assertSame(testentityProfile.getName(), entityProfile.getName());

    }

    @Test
    public void testGetProfiles() {
        final List<EntityProfileData> entityProfileDatas = new ArrayList<EntityProfileData>();
        entityProfileDatas.add(entityProfileData);
        when(persistenceManager.getAllEntityItems(EntityProfileData.class)).thenReturn(entityProfileDatas);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfileMapper);
        when(entityProfileMapper.toAPIFromModel(entityProfileData)).thenReturn(entityProfile);
        entityProfilePersistenceHandler.getProfiles(ProfileType.ENTITY_PROFILE);
        Mockito.verify(entityProfileMapper).toAPIFromModel(entityProfileData);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDeleteProfile() {
        when(persistenceManager.findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        entityProfilePersistenceHandler.deleteProfile(entityProfile);
        Mockito.verify(persistenceManager).findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH);
    }

    @Test(expected = ProfileServiceException.class)
    public void testDeleteProfile_ProfileServiceException() {
        when(persistenceManager.findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(entityProfileData);
        entityProfilePersistenceHandler.deleteProfile(entityProfile);
    }

    @Test(expected = ProfileServiceException.class)
    public void testDeleteProfile_PersistenceException() {
        when(persistenceManager.findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(entityProfileData);
        entityProfilePersistenceHandler.deleteProfile(entityProfile);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ProfileInUseException.class)
    public void testDeleteProfile_ProfileEntity() {
        final List<EntityData> endEntities = new ArrayList<EntityData>();
        final EntityData entityData1 = new EntityData();
        entityData1.setId(123);
        endEntities.add(entityData1);
        final Map<String, Object> hmAttributes = new HashMap<String, Object>();
        hmAttributes.put("entity_profile_id", entityProfileData.getId());
        when(persistenceManager.findEntitiesByAttributes(EntityData.class, entityQuery, hmAttributes)).thenReturn(endEntities);
        when(persistenceManager.findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        entityProfilePersistenceHandler.deleteProfile(entityProfile);
        Mockito.verify(persistenceManager).findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ProfileInUseException.class)
    public void testDeleteProfile_ProfileCAEntity() {
        final List<CAEntityData> caEntities = new ArrayList<CAEntityData>();
        final CAEntityData caentityData1 = new CAEntityData();
        caentityData1.setId(111);
        caEntities.add(caentityData1);
        final Map<String, Object> hmAttributes = new HashMap<String, Object>();
        hmAttributes.put("entity_profile_id", entityProfileData.getId());
        when(persistenceManager.findEntitiesByAttributes(CAEntityData.class, caEntityQuery, hmAttributes)).thenReturn(caEntities);
        when(persistenceManager.findEntityByIdAndName(EntityProfileData.class, entityProfile.getId(), entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        entityProfilePersistenceHandler.deleteProfile(entityProfile);
    }

    @Test
    public void testIsNameAvailable_Name_False() {
        when(persistenceManager.findEntityByName(EntityProfileData.class, "TestEP", EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        assertEquals(entityProfilePersistenceHandler.isNameAvailable("TestEP"), false);
        Mockito.verify(persistenceManager).findEntityByName(EntityProfileData.class, "TestEP", EntityProfileSetUpData.NAME_PATH);
    }

    @Test
    public void testIsNameAvailable_Name_True() {
        when(persistenceManager.findEntityByName(EntityProfileData.class, "TestEP", EntityProfileSetUpData.NAME_PATH)).thenReturn(null);
        assertTrue(entityProfilePersistenceHandler.isNameAvailable("TestEP"));
    }

    @Test
    public void testGetEntityProfilesByCategory() {
        final List<EntityProfileData> entityProfileDatas = new ArrayList<EntityProfileData>();
        entityProfileDatas.add(entityProfileData);
        final List<Object> entityProfiles = new ArrayList<Object>();
        entityProfile.setId(2L);
        entityProfiles.add(entityProfile);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityCategoryData);

        when(persistenceManager.findEntitiesWhere(EntityProfileData.class, input)).thenReturn(entityProfileDatas);
        when(profileModelMapperFactory.getProfileModelMapper(ProfileType.ENTITY_PROFILE)).thenReturn(entityProfile_Mapper);
        when(entityProfile_Mapper.toAPIModelList(Matchers.anyList())).thenReturn(entityProfiles);
        assertNotNull(entityProfilePersistenceHandler.getEntityProfilesByCategory(entityCategory).get(0));

    }

    @Test(expected = ProfileServiceException.class)
    public void testGetEntityProfilesByCategory_ProfileServiceException() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityCategoryData);
        Mockito.doThrow(new PersistenceException()).when(profileModelMapperFactory).getProfileModelMapper(ProfileType.ENTITY_PROFILE);
        entityProfilePersistenceHandler.getEntityProfilesByCategory(entityCategory);
    }

    @Test(expected = InvalidProfileException.class)
    public void testGetEntityProfilesByCategory_Exception() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityCategoryData);
        Mockito.doThrow(new InvalidProfileException()).when(profileModelMapperFactory).getProfileModelMapper(ProfileType.ENTITY_PROFILE);
        entityProfilePersistenceHandler.getEntityProfilesByCategory(entityCategory);
    }

    @Test
    public void testgetProfilesCountByFilterwithoutTypes() {

        final ProfilesFilter profilesFilter = getProfilesFilter();
        profilesFilter.setType(null);

        Mockito.when(persistenceManager.getEntitiesCount(EntityProfileData.class)).thenReturn((long) 1);

        final int count = entityProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(1, count);
    }

    @Test(expected = ProfileServiceException.class)
    public void testgetProfilesCountByFilterwithoutTypesException() {

        final ProfilesFilter profilesFilter = getProfilesFilter();
        profilesFilter.setType(null);

        Mockito.when(persistenceManager.getEntitiesCount(EntityProfileData.class)).thenThrow(new ProfileServiceException());

        Assert.assertNotNull(entityProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter));

    }

    @Test
    public void testgetProfilesCountByFilter() {

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final Map<String, Object> attributes = new HashMap<String, Object>();

        attributes.put("entityProfileName", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        Mockito.when(persistenceManager.findEntitiesCountByAttributes("select * from test", attributes)).thenReturn((long) 1);

        final int count = entityProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(0, count);
    }

    /**
     * this method tests the get active profiles in positive scenario
     */
    @Test
    public void testgetActiveProfiles() {
        final ProfileType profileType = ProfileType.ENTITY_PROFILE;
        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();

        Mockito.when(entityProfilePersistenceHandler.getActiveProfiles(EntityProfileData.class, profileType)).thenReturn(entityProfiles);
        final Profiles profiles = entityProfilePersistenceHandler.getActiveProfiles(profileType, true);

        Assert.assertEquals(entityProfiles, profiles.getEntityProfiles());
    }

    /**
     * this method tests the get active profiles in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetActiveProfiles_ProfileServiceException() {
        final ProfileType profileType = ProfileType.ENTITY_PROFILE;
        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();

        Mockito.when(entityProfilePersistenceHandler.getActiveProfiles(EntityProfileData.class, profileType)).thenThrow(new PersistenceException());
        final Profiles profiles = entityProfilePersistenceHandler.getActiveProfiles(profileType, true);

        Assert.assertEquals(entityProfiles, profiles.getEntityProfiles());
    }

    /**
     * this method tests the get active profiles in positive scenario
     */
    @Test
    public void testgetForActiveProfilesIdAndName() {
        final ProfileType profileType = ProfileType.ENTITY_PROFILE;
        final Object[] obj = new Object[] { ID, PROFILE_NAME };

        final List<Object[]> entities = new ArrayList<Object[]>();
        entities.add(obj);

        Mockito.when(entityProfilePersistenceHandler.fetchActiveProfilesIdAndName(queryForFetchActiveEntityProfiles)).thenReturn(entities);

        final Profiles profiles = entityProfilePersistenceHandler.getActiveProfiles(profileType, false);
        final List<EntityProfile> entityProfiles = profiles.getEntityProfiles();

        Assert.assertEquals(123765676, entityProfiles.get(0).getId());
        Assert.assertEquals(PROFILE_NAME, entityProfiles.get(0).getName());
    }

    /**
     * this method tests the get active profiles in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetForActiveProfilesIdAndName_ProfileServiceException() {
        final ProfileType profileType = ProfileType.ENTITY_PROFILE;
        final Object[] obj = new Object[] { ID, PROFILE_NAME };

        final List<Object[]> entities = new ArrayList<Object[]>();
        entities.add(obj);

        Mockito.when(entityProfilePersistenceHandler.fetchActiveProfilesIdAndName(queryForFetchActiveEntityProfiles)).thenThrow(new PersistenceException());

        final Profiles profiles = entityProfilePersistenceHandler.getActiveProfiles(profileType, false);
        final List<EntityProfile> entityProfiles = profiles.getEntityProfiles();

        Assert.assertEquals(123765676, entityProfiles.get(0).getId());
        Assert.assertEquals(PROFILE_NAME, entityProfiles.get(0).getName());
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

        types.add(ProfileType.ENTITY_PROFILE);

        profilesFilter.setType(types);

        return profilesFilter;
    }

}