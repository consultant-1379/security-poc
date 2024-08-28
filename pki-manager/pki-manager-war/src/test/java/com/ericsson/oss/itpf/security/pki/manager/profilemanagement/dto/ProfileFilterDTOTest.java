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

@RunWith(MockitoJUnitRunner.class)
public class ProfileFilterDTOTest {

    ProfileFilterDTO profileFilterDTO;
    ProfileFilterDTO expectedProfileFilterDTO;

    @Before
    public void setup() {
        profileFilterDTO = getProfileFilterDTO();
        expectedProfileFilterDTO = getProfileFilterDTO();
    }

    @Test
    public void testEquals() {

        profileFilterDTO.toString();
        profileFilterDTO.equals(expectedProfileFilterDTO);
        assertEquals(profileFilterDTO, expectedProfileFilterDTO);

    }

    @Test
    public void testEqualsSame() {

        profileFilterDTO.toString();
        profileFilterDTO.equals(expectedProfileFilterDTO);
        profileFilterDTO.hashCode();
        assertEquals(profileFilterDTO, profileFilterDTO);

    }

    @Test
    public void testEqualsNull() {

        profileFilterDTO.toString();
        assertEquals(expectedProfileFilterDTO, profileFilterDTO);
    }

    @Test
    public void testEqualsNameNull() {

        profileFilterDTO.toString();
        profileFilterDTO.setName(null);
        profileFilterDTO.equals(expectedProfileFilterDTO);
        assertNotEquals(profileFilterDTO, expectedProfileFilterDTO);

    }

    @Test
    public void testEqualstypeNull() {
        profileFilterDTO.setName(expectedProfileFilterDTO.getName());
        profileFilterDTO.toString();
        profileFilterDTO.setType(null);
        profileFilterDTO.equals(expectedProfileFilterDTO);
        assertNotEquals(profileFilterDTO, expectedProfileFilterDTO);

    }

    @Test
    public void testEqualstatuseNull() {
        profileFilterDTO.setType(expectedProfileFilterDTO.getType());
        profileFilterDTO.toString();
        profileFilterDTO.setStatus(null);
        profileFilterDTO.equals(expectedProfileFilterDTO);
        assertNotEquals(profileFilterDTO, expectedProfileFilterDTO);

    }

    @Test
    public void testEqualStatusNull() {

        profileFilterDTO.setStatus(null);
        assertFalse(profileFilterDTO.equals(null));

    }

    @Test
    public void testEqualsDiffType() {
        assertFalse(profileFilterDTO.equals(new ProfilesDTO()));

    }

    @Test
    public void testNotEqualDifffName() {

        expectedProfileFilterDTO.setName("Nowtest");
        assertFalse(profileFilterDTO.equals(expectedProfileFilterDTO));

    }

    @Test
    public void testNotEqualsDiffType() {

        final List<ProfileType> types = new ArrayList<ProfileType>();
        types.add(ProfileType.ENTITY_PROFILE);
        expectedProfileFilterDTO.setType(types);

        assertFalse(profileFilterDTO.equals(expectedProfileFilterDTO));
        expectedProfileFilterDTO.setType(profileFilterDTO.getType());
    }

    @Test
    public void testNotEqualsStatusNull() {

        final ProfileStatusFilter status = new ProfileStatusFilter();
        status.setActive(true);
        status.setInactive(false);
        expectedProfileFilterDTO.setStatus(status);
        assertFalse(profileFilterDTO.equals(expectedProfileFilterDTO));
        expectedProfileFilterDTO.setStatus(profileFilterDTO.getStatus());

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