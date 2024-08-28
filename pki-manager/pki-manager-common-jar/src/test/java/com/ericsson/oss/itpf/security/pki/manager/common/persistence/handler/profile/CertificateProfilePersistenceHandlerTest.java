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

import java.math.BigInteger;
import java.util.*;

import javax.persistence.PersistenceException;
import javax.persistence.TransactionRequiredException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.CertificateProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.ProfileModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * Test class for {@link CertificateProfilePersistenceHandler}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateProfilePersistenceHandlerTest {
    @InjectMocks
    private CertificateProfilePersistenceHandler<CertificateProfile> certificateProfilePersistenceHandler;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateProfilePersistenceHandler.class);

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private ProfileModelMapperFactory profileModelMapperFactory;

    @Mock
    private CertificateProfileMapper certificateProfileMapper;

    private final static String NAME_PATH = "name";
    private final static String PROFILE_NAME = "TestCP";
    private final static BigInteger ID = new BigInteger("123765676");

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private List<EntityProfileData> entityProfileDatas;

    private final static String queryForFetchActiveCertProfiles = "select id,name from certificateprofile where is_active=true";

    /**
     * Method to provide dummy data for tests.
     * 
     * @throws DatatypeConfigurationException
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();
        entityProfileDatas = new ArrayList<EntityProfileData>();
    }

    /**
     * Method to test getProfiles Method in positive scenario.
     */
    @Test
    public void testGetProfiles() {
        final List<CertificateProfileData> certificateProfiles = new ArrayList<CertificateProfileData>();
        certificateProfiles.add(certificateProfileData);
        Mockito.when(persistenceManager.getAllEntityItems(CertificateProfileData.class)).thenReturn(certificateProfiles);
        Mockito.when(profileModelMapperFactory.getProfileModelMapper(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfileMapper);
        Mockito.when(certificateProfileMapper.toAPIFromModel(certificateProfileData)).thenReturn(certificateProfile);
        Assert.assertEquals(certificateProfilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE).getCertificateProfiles().get(0).getName(), certificateProfile.getName());
    }

    /**
     * Method to test getProfiles Method in negative scenario.
     */
    @Test
    public void testGetProfilesWithInputNull() {
        final List<CertificateProfile> listCertificateProfiles = new ArrayList<CertificateProfile>();
        Assert.assertEquals(certificateProfilePersistenceHandler.getProfiles(null).getCertificateProfiles(), listCertificateProfiles);
    }

    /**
     * Method to test getProfiles Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfilesForCertificateProfiles() {
        final List<CertificateProfileData> certificateProfiles = new ArrayList<CertificateProfileData>();
        certificateProfiles.add(certificateProfileData);
        Mockito.when(profileModelMapperFactory.getProfileModelMapper(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfileMapper);
        Mockito.when(certificateProfileMapper.toAPIFromModel(certificateProfileData)).thenThrow(PersistenceException.class);
        Mockito.when(persistenceManager.getAllEntityItems(CertificateProfileData.class)).thenReturn(certificateProfiles);
        certificateProfilePersistenceHandler.getProfiles(ProfileType.CERTIFICATE_PROFILE).getCertificateProfiles();
    }

    /**
     * Method to test getProfile Method in positive scenario.
     */
    @Test
    public void testGetProfile() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        Mockito.when(profileModelMapperFactory.getProfileModelMapper(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfileMapper);
        Mockito.when(certificateProfileMapper.toAPIFromModel(certificateProfileData)).thenReturn(certificateProfile);
        Assert.assertEquals(certificateProfilePersistenceHandler.getProfile(certificateProfile).getName(), certificateProfile.getName());
    }

    /**
     * Method to test getProfile Method in negative scenario.
     */
    @Test(expected = NullPointerException.class)
    public void testGetProfileWithNull() {
        certificateProfilePersistenceHandler.getProfile(null);
    }

    /**
     * Method to test getProfile Method in negative scenario.
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetProfileWithProfileNotFoundException() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(null);
        Mockito.when(profileModelMapperFactory.getProfileModelMapper(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfileMapper);
        Mockito.when(certificateProfileMapper.toAPIFromModel(certificateProfileData)).thenReturn(certificateProfile);
        certificateProfilePersistenceHandler.getProfile(certificateProfile);
    }

    /**
     * Method to test getProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testGetProfileWithProfileServiceException() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        Mockito.when(profileModelMapperFactory.getProfileModelMapper(ProfileType.CERTIFICATE_PROFILE)).thenReturn(certificateProfileMapper);
        Mockito.when(certificateProfileMapper.toAPIFromModel(certificateProfileData)).thenThrow(new ProfileServiceException());
        certificateProfilePersistenceHandler.getProfile(certificateProfile);
    }

    /**
     * Method to test deleteProfile Method in positive scenario.
     */
    @Test
    public void testDeleteProfile() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        certificateProfilePersistenceHandler.deleteProfile(certificateProfile);
    }

    /**
     * Method to test deleteProfile Method in negative scenario.
     */
    @Test(expected = NullPointerException.class)
    public void testDeleteProfileWithNull() {
        certificateProfilePersistenceHandler.deleteProfile(null);
    }

    /**
     * Method to test deleteProfile Method in negative scenario.
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testDeleteProfileWithNameNull() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(null);
        certificateProfilePersistenceHandler.deleteProfile(certificateProfile);
    }

    /**
     * Method to test deleteProfile Method in negative scenario.
     */
    @Test(expected = ProfileInUseException.class)
    public void testDeleteProfileWithProfileInUseException() {
        final EntityProfileData entityProfileData = new EntityProfileData();
        entityProfileData.setId(111);
        entityProfileData.setName("TestEP");
        entityProfileDatas.add(entityProfileData);

        final HashMap<String, Object> attributes = new HashMap<String, Object>();

        attributes.put("certificateProfileData", certificateProfile.getId());
        attributes.put("active", true);
        Mockito.when(persistenceManager.findEntitiesWhere(EntityProfileData.class, attributes)).thenReturn(entityProfileDatas);

        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        certificateProfilePersistenceHandler.deleteProfile(certificateProfile);
    }

    /**
     * Method to test deleteProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testDeleteProfileWithProfileServiceException() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).deleteEntity(certificateProfileData);
        certificateProfilePersistenceHandler.deleteProfile(certificateProfile);
    }

    /**
     * Method to test deleteProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testDeleteProfileWithException() {
        Mockito.when(persistenceManager.findEntityByIdAndName(CertificateProfileData.class, certificateProfile.getId(), certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        Mockito.doThrow(new ProfileServiceException()).when(persistenceManager).deleteEntity(certificateProfileData);
        certificateProfilePersistenceHandler.deleteProfile(certificateProfile);
    }

    /**
     * Method to test isNameAvailable Method in negative scenario.
     */
    @Test
    public void testIsNameAvailableFalse() {
        Mockito.when(persistenceManager.findEntityByName(CertificateProfileData.class, certificateProfile.getName(), NAME_PATH)).thenReturn(certificateProfileData);
        Assert.assertFalse(certificateProfilePersistenceHandler.isNameAvailable(certificateProfile.getName()));
    }

    /**
     * Method to test isNameAvailable Method in positive scenario.
     */
    @Test
    public void testIsNameAvailableTrue() {
        Mockito.when(persistenceManager.findEntityByName(CertificateProfileData.class, certificateProfile.getName(), NAME_PATH)).thenReturn(null);
        Assert.assertTrue(certificateProfilePersistenceHandler.isNameAvailable(certificateProfile.getName()));
    }

    /**
     * Method to test getProfiles count by Filter Method in positive scenario.
     */
    @Test
    public void testgetProfilesCountByFilterwithFilter() {

        final ProfilesFilter profilesFilter = getProfilesFilter();
        final String queryForCertificateProfilesCountByFilter = "select * from test";
        final Map<String, Object> attributes = new HashMap<String, Object>();

        attributes.put("certificateProfileName", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        final long countmocked = 1;

        Mockito.when(persistenceManager.findEntitiesCountByAttributes(queryForCertificateProfilesCountByFilter, attributes)).thenReturn(countmocked);

        final int count = certificateProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(0, count);

    }

    /**
     * Method to test getProfiles count by Filter Method in positive scenario.
     */
    @Test
    public void testgetProfilesCountByFilterwithoutFilter() {

        final ProfilesFilter profilesFilter = getProfilesFilter();
        profilesFilter.setType(null);

        Mockito.when(persistenceManager.getEntitiesCount(CertificateProfileData.class)).thenReturn((long) 1);

        final int count = certificateProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(1, count);

    }

    /**
     * Method to test getProfiles count by Filter Method in throw Exception.
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetProfilesCountByFilterwithoutFilterException() {

        final ProfilesFilter profilesFilter = getProfilesFilter();
        profilesFilter.setType(null);

        Mockito.when(persistenceManager.getEntitiesCount(CertificateProfileData.class)).thenThrow(new ProfileServiceException());

        Assert.assertNotNull(certificateProfilePersistenceHandler.getProfilesCountByFilter(profilesFilter));
    }

    /**
     * this method tests getActiveProfiles for positive scenario
     */
    @Test
    public void testgetActiveProfilesForCompleteProfile() {
        final ProfileType profileType = ProfileType.CERTIFICATE_PROFILE;
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();

        Mockito.when(certificateProfilePersistenceHandler.getActiveProfiles(CertificateProfileData.class, profileType)).thenReturn(certificateProfiles);
        final Profiles profiles = certificateProfilePersistenceHandler.getActiveProfiles(profileType, true);

        Assert.assertEquals(certificateProfiles, profiles.getCertificateProfiles());
    }

    /**
     * this method tests getActiveProfiles for negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetActiveProfilesForCompleteProfile_ProfileServiceException() {
        final ProfileType profileType = ProfileType.CERTIFICATE_PROFILE;
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();

        Mockito.when(certificateProfilePersistenceHandler.getActiveProfiles(CertificateProfileData.class, profileType)).thenThrow(new PersistenceException());
        final Profiles profiles = certificateProfilePersistenceHandler.getActiveProfiles(profileType, true);

        Assert.assertEquals(certificateProfiles, profiles.getCertificateProfiles());
    }

    /**
     * this method tests getActiveProfiles for positive scenario
     */
    @Test
    public void testgetActiveProfilesForActiveProfilesIdAndName() {
        final ProfileType profileType = ProfileType.CERTIFICATE_PROFILE;
        final Object[] obj = new Object[] { ID, PROFILE_NAME };

        final List<Object[]> entities = new ArrayList<Object[]>();
        entities.add(obj);

        Mockito.when(certificateProfilePersistenceHandler.fetchActiveProfilesIdAndName(queryForFetchActiveCertProfiles)).thenReturn(entities);

        final Profiles profiles = certificateProfilePersistenceHandler.getActiveProfiles(profileType, false);
        final List<CertificateProfile> certificateProfiles = profiles.getCertificateProfiles();

        Assert.assertEquals(123765676, certificateProfiles.get(0).getId());
        Assert.assertEquals(PROFILE_NAME, certificateProfiles.get(0).getName());
    }

    /**
     * this method tests getActiveProfiles for negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testgetActiveProfilesForActiveProfilesIdAndName_ProfileServiceException() {
        final ProfileType profileType = ProfileType.CERTIFICATE_PROFILE;
        final Object[] obj = new Object[] { ID, PROFILE_NAME };

        final List<Object[]> entities = new ArrayList<Object[]>();
        entities.add(obj);

        Mockito.when(certificateProfilePersistenceHandler.fetchActiveProfilesIdAndName(queryForFetchActiveCertProfiles)).thenThrow(new PersistenceException());

        final Profiles profiles = certificateProfilePersistenceHandler.getActiveProfiles(profileType, false);
        final List<CertificateProfile> certificateProfiles = profiles.getCertificateProfiles();

        Assert.assertEquals(123765676, certificateProfiles.get(0).getId());
        Assert.assertEquals(PROFILE_NAME, certificateProfiles.get(0).getName());
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

        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);

        return profilesFilter;
    }
}
