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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.validators;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfileFilterDTO;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfileStatusFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

/**
 * Test class for {@link DTOValidator} Profile management
 * 
 * @author
 * @version
 */

@RunWith(MockitoJUnitRunner.class)
public class DTOValidatorTest {

    @InjectMocks
    DTOValidator dtoValidator;

    @Mock
    Logger logger;

    ProfileFilterDTO profileFilterDTO;

    @Before
    public void setUp() {

        profileFilterDTO = getProfileFilterDTO();

    }

    /**
     * Method for testing validateProfileFilterDTO()
     * 
     * 
     * 
     */

    @Test
    public void testValidateProfileFilterDTO() {

        final boolean isvalid = dtoValidator.validateProfileFilterDTO(profileFilterDTO);
        assertEquals(true, isvalid);

    }

    /**
     * Method for testing validateProfileFilterDTO() with null type
     * 
     * 
     */

    @Test
    public void testValidateProfileFilterDTOwithTypeNull() {

        profileFilterDTO = getProfileFilterDTO();
        profileFilterDTO.setType(null);
        final boolean isvalid = dtoValidator.validateProfileFilterDTO(profileFilterDTO);
        assertEquals(false, isvalid);

    }

    /**
     * Method for testing validateProfileFilterDTO() with null status
     * 
     * 
     */
    @Test
    public void testValidateProfileFilterDTOwithStatusNull() {
        profileFilterDTO = getProfileFilterDTO();
        profileFilterDTO.setStatus(null);
        final boolean isvalid = dtoValidator.validateProfileFilterDTO(profileFilterDTO);
        assertEquals(false, isvalid);

    }

    /**
     * Method for testing validateProfileFilterDTO() with null name
     * 
     * 
     */
    @Test
    public void testValidateProfileFilterDTOwithNameNumm() {
        profileFilterDTO = getProfileFilterDTO();
        profileFilterDTO.setName(null);
        final boolean isvalid = dtoValidator.validateProfileFilterDTO(profileFilterDTO);
        assertEquals(false, isvalid);

    }

    /**
     * Method for testing validateProfileFilterDTO() with null name
     * 
     * 
     */
    @Test
    public void testValidateProfileFilterDTOwithNoActive() {
        profileFilterDTO = getProfileFilterDTO();
        final ProfileStatusFilter status = profileFilterDTO.getStatus();
        status.setActive(false);
        status.setInactive(false);
        profileFilterDTO.setStatus(status);
        final boolean isvalid = dtoValidator.validateProfileFilterDTO(profileFilterDTO);
        assertEquals(false, isvalid);

    }

    /**
     * Method for testing validateProfileFilterDTO() with all null values
     * 
     * 
     */
    @Test
    public void testValidateProfileFilterDTOwithAllNull() {
        profileFilterDTO = getProfileFilterDTO();
        profileFilterDTO.setStatus(null);
        profileFilterDTO.setName(null);
        profileFilterDTO.setType(null);
        final boolean isvalid = dtoValidator.validateProfileFilterDTO(profileFilterDTO);
        assertEquals(true, isvalid);

    }

    /**
     * Method for testing validateProfilesDTO() with positive scenario
     * 
     * 
     */

    @Test
    public void testvalidateProfilesDTO() {
        final ProfilesDTO profilesDTO = getProfilesDTO();
        final boolean isvalid = dtoValidator.validateProfilesDTO(profilesDTO);
        assertEquals(true, isvalid);
    }

    /**
     * Method for testing validateProfilesDTO() with Negative scenario
     * 
     * 
     */
    @Test
    public void testValidateProfilesDTOWithOffsetZeroAndLimitZero() {
        final ProfilesDTO profilesDTO = getProfilesDTO();
        profilesDTO.setFilter(getProfileFilterDTO());
        profilesDTO.setLimit(0);
        profilesDTO.setOffset(0);
        final boolean isvalid = dtoValidator.validateProfilesDTO(profilesDTO);
        assertEquals(false, isvalid);
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

    private ProfilesDTO getProfilesDTO() {

        final ProfilesDTO profilesDTO = new ProfilesDTO();
        profilesDTO.setLimit(10);
        profilesDTO.setOffset(1);
        profilesDTO.setFilter(getProfileFilterDTO());
        return profilesDTO;
    }

}
