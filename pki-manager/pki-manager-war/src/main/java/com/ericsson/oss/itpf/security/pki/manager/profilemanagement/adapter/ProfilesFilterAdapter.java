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

import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfileFilterDTO;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

/**
 * A adapter class to convert the {@link ProfileFilterDTO} and {@link ProfilesDTO} objects into API {@link ProfilesFilter} object.
 */
public class ProfilesFilterAdapter {

    /**
     * Converts the {@link ProfileFilterDTO} to {@link ProfilesFilter} object
     *
     * @param profileFilterDTO
     *            ProfileFilterDTO object containing filter conditions based on which profiles has to be filtered.
     *
     * @return the {@link ProfilesFilter} Object containing type, name, active, inactive, offset and limit.
     *
     */
    public ProfilesFilter toProfilesFilter(final ProfileFilterDTO profileFilterDTO) {
        ProfilesFilter profilesFilter = new ProfilesFilter();

        if (!ValidationUtils.isNullOrEmpty(profileFilterDTO.getType())) {

            profilesFilter = fillFilterDTO(profilesFilter, profileFilterDTO);
        }

        return profilesFilter;
    }

    /**
     * Converts the {@link ProfilesDTO} to {@link ProfilesFilter} object
     *
     * @param profilesDTO
     *            ProfilesDTO object specifying filter conditions, offset and limit based on which entities has to be filtered.
     *
     * @return the {@link ProfilesFilter} Object containing type, name, active, inactive, offset and limit.
     *
     */
    public ProfilesFilter toProfilesFilter(final ProfilesDTO profilesDTO) {
        ProfilesFilter profilesFilter = new ProfilesFilter();
        ProfileFilterDTO profileFilterDTO = null;

        if (profilesDTO != null) {

            profileFilterDTO = profilesDTO.getFilter();

            profilesFilter.setOffset(profilesDTO.getOffset());
            profilesFilter.setLimit(profilesDTO.getLimit());

        }

        if (profileFilterDTO != null) {

            profilesFilter = fillFilterDTO(profilesFilter, profileFilterDTO);
        }

        return profilesFilter;
    }

    private ProfilesFilter fillFilterDTO(final ProfilesFilter profilesFilter, final ProfileFilterDTO profileFilterDTO) {

        if (profileFilterDTO != null) {
            final ProfileStatusFilter profileStatusFilter = new ProfileStatusFilter();

            profileStatusFilter.setActive(profileFilterDTO.getStatus().isActive());
            profileStatusFilter.setInactive(profileFilterDTO.getStatus().isInactive());

            profilesFilter.setName(profileFilterDTO.getName());
            profilesFilter.setType(profileFilterDTO.getType());
            profilesFilter.setStatus(profileStatusFilter);

        }

        return profilesFilter;
    }

}
