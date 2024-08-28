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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.adapter;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.*;

/**
 * Test class for {@link ProfilesFilterAdapter}
 * 
 * 
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfilesFilterAdapterTest {

    @InjectMocks
    ProfilesFilterAdapter profilesFilterAdapter;

    @Before
    public void setUp() {

        profilesFilterAdapter = new ProfilesFilterAdapter();

    }

    /**
     * Method for testing method for converting ProfileDTO to ProfileFilter for Fetch.
     * 
     * 
     */
    @Test
    public void testToProfilesFilterForFetch() {

        final ProfilesDTO profilesDTO = getProfilesDTO();
        final ProfilesFilter profilesFilter = profilesFilterAdapter.toProfilesFilter(profilesDTO);
        assertEquals(getProfilesFilter(), profilesFilter);

    }

    /**
     * Method for testing method for converting ProfileFilterDTO to ProfileFilter for Count.
     * 
     * 
     */
    @Test
    public void testToProfilesFilterForCount() {

        final ProfileFilterDTO profilefilterDTO = getProfileFilterDTO();

        final ProfilesFilter profilesFilter = profilesFilterAdapter.toProfilesFilter(profilefilterDTO);
        final ProfilesFilter expectedProfilesFilter = getProfilesFilter();
        expectedProfilesFilter.setLimit(0);
        expectedProfilesFilter.setOffset(0);

        assertEquals(expectedProfilesFilter, profilesFilter);

    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfilesDTO getProfilesDTO() {

        final ProfilesDTO profilesDTO = new ProfilesDTO();
        profilesDTO.setLimit(10);
        profilesDTO.setOffset(1);
        profilesDTO.setFilter(getProfileFilterDTO());
        return profilesDTO;
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

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfileFilterDTO getProfileFilterDTO() {

        final ProfileFilterDTO profilefilterDTO = new ProfileFilterDTO();

        profilefilterDTO.setName("Test%");

        final ProfileStatusFilter status = new ProfileStatusFilter();
        status.setActive(true);
        status.setInactive(true);

        profilefilterDTO.setStatus(status);

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilefilterDTO.setType(types);

        return profilefilterDTO;
    }

}
