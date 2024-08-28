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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

@RunWith(MockitoJUnitRunner.class)
public class ProfilesDTOTest {

    ProfilesDTO profilesDTO;
    ProfilesDTO expectedProfilesDTO;

    @Before
    public void setUp() {
        profilesDTO = getProfilesDTO();
        profilesDTO.hashCode();
        profilesDTO.toString();
        expectedProfilesDTO = getProfilesDTO();
    }

    @Test
    public void testEquals() {

        assertEquals(profilesDTO, expectedProfilesDTO);

    }

    @Test
    public void testEqualsSame() {
        assertEquals(profilesDTO, profilesDTO);

    }

    @Test
    public void testNotEqualsSameClass() {
        assertNotEquals(profilesDTO, new ProfilesFilter());

    }

    @Test
    public void testNotEqualsNoFilter() {
        profilesDTO.setFilter(null);
        assertNotEquals(profilesDTO, expectedProfilesDTO);

    }

    @Test
    public void testNotEqualsNullFilter() {
        assertFalse(profilesDTO.equals(null));

    }

    @Test
    public void testNotEqualsDiffFilter() {

        profilesDTO.setFilter(getProfileFilterDTO());
        final ProfileFilterDTO profileFilter = expectedProfilesDTO.getFilter();
        profileFilter.setName("Testing2");
        expectedProfilesDTO.setFilter(profileFilter);
        assertNotEquals(profilesDTO, expectedProfilesDTO);

    }

    @Test
    public void testNotEqualsDiffLimit() {

        expectedProfilesDTO.setFilter(profilesDTO.getFilter());
        expectedProfilesDTO.setLimit(100);
        assertNotEquals(profilesDTO, expectedProfilesDTO);

    }

    @Test
    public void testNotEqualsDiffOffset() {
        expectedProfilesDTO.setOffset(100);
        assertNotEquals(profilesDTO, expectedProfilesDTO);

    }

    private ProfilesDTO getProfilesDTO() {

        final ProfilesDTO profilesDTO = new ProfilesDTO();
        profilesDTO.setLimit(10);
        profilesDTO.setOffset(1);
        profilesDTO.setFilter(getProfileFilterDTO());
        return profilesDTO;
    }

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
