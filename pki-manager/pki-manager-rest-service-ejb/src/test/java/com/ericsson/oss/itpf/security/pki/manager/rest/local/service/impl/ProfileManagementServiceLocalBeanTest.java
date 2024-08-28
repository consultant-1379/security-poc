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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.ProfileManager;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl.setup.CertificateProfileSetUpToTest;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementServiceLocalBeanTest {

    @InjectMocks
    ProfileManagementServiceLocalBean profileManagementServiceLocalBean;

    @Mock
    ProfileManager profileManager;

    @Spy
    final Logger logger = LoggerFactory.getLogger(ProfileManagementServiceLocalBeanTest.class);

    CertificateProfile certificateProfile;
    CertificateProfileSetUpToTest certificateProfileSetUpToTest;
    List<CertificateProfile> certProfielList = new ArrayList<CertificateProfile>();
    Profiles profiles = new Profiles();
    List<AbstractProfile> profilesList;

    @Before
    public void setUp() throws DatatypeConfigurationException {

        certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certProfielList.add(certificateProfile);
        profiles.setCertificateProfiles(certProfielList);

        profilesList = new ArrayList<AbstractProfile>();
        profilesList.add(certificateProfile);
    }

    /**
     * Method to test getProfilesCountByFilter in positive scenario.
     * 
     */

    @Test
    public void testGetProfilesCountByFilter() {

        final ProfilesFilter profilesFilter = getProfilesFilter();

        when(profileManager.getProfilesCountByFilter(profilesFilter)).thenReturn(3);

        final int count = profileManagementServiceLocalBean.getProfilesCountByFilter(profilesFilter);

        Assert.assertEquals(count, 3);
    }

    /**
     * Method to test get profile details in Union case positive scenario.
     */
    @Test
    public void testGetProfileDetails() {
        final ProfilesFilter profilesFilter = getProfilesFilter();

        when(profileManager.getProfileDetails(profilesFilter)).thenReturn(profilesList);

        final List<AbstractProfile> expedtedProfilesList = profileManagementServiceLocalBean.getProfileDetails(profilesFilter);

        Assert.assertEquals(profilesList, expedtedProfilesList);
    }

    /**
     * Method to testfetchActiveProfiles in positive scenario.
     */
    @Test
    public void testfetchActiveProfiles() {
        final ProfileType[] profileTypes = ProfileType.values();
        final Profiles profiles = new Profiles();

        Mockito.when(profileManager.getActiveProfiles(profileTypes, false)).thenReturn(profiles);
        final Profiles activeProfiles = profileManagementServiceLocalBean.fetchActiveProfilesIdAndName(profileTypes);

        Assert.assertEquals(profiles, activeProfiles);
    }

    /**
     * Method to testfetchActiveProfiles in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testfetchActiveProfiles_ProfileServiceException() {
        final ProfileType[] profileTypes = ProfileType.values();
        final Profiles profiles = new Profiles();

        Mockito.when(profileManager.getActiveProfiles(profileTypes, false)).thenThrow(new ProfileServiceException());
        final Profiles activeProfiles = profileManagementServiceLocalBean.fetchActiveProfilesIdAndName(profileTypes);

        Assert.assertEquals(profiles, activeProfiles);
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
