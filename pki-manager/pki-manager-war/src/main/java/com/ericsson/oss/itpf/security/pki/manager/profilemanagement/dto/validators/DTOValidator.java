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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.*;

/**
 * This class validates all the values given in DTO's {@link ProfilesDTO} , {@link ProfileFilterDTO}.
 *
 */
public class DTOValidator {

    @Inject
    private Logger logger;

    /**
     * This method validates the profile filter DTO attributes given as input
     *
     * @param profileFilterDTO
     *            ProfileFilterDTO object containing filter conditions based on which profiles has to be filtered.
     * @return boolean returns true if all the attributes are valid or else false
     *
     */
    public boolean validateProfileFilterDTO(final ProfileFilterDTO profileFilterDTO) {
        boolean isValidProfileFilterDTO = true;

        if (ValidationUtils.isNullOrEmpty(profileFilterDTO.getType()) && ValidationUtils.isNullOrEmpty(profileFilterDTO.getName()) && profileFilterDTO.getStatus() == null) {
            isValidProfileFilterDTO = true;
            return isValidProfileFilterDTO;
        }

        if (ValidationUtils.isNullOrEmpty(profileFilterDTO.getType())) {
            isValidProfileFilterDTO = false;
            return isValidProfileFilterDTO;
        }

        if (profileFilterDTO.getName() == null) {
            isValidProfileFilterDTO = false;
            return isValidProfileFilterDTO;
        }

        final ProfileStatusFilter status = profileFilterDTO.getStatus();

        if (status == null) {
            isValidProfileFilterDTO = false;
            return isValidProfileFilterDTO;
        }

        if (!(status.isActive() || status.isInactive())) {
            isValidProfileFilterDTO = false;
            return isValidProfileFilterDTO;
        }

        return isValidProfileFilterDTO;
    }

    /**
     * This method validates the profiles DTO attributes given as input
     *
     * @param profilesDTO
     *            ProfilesDTO object specifying filter conditions, offset and limit based on which entities has to be filtered
     * @return boolean returns true if all the attributes are valid or else false
     *
     */
    public boolean validateProfilesDTO(final ProfilesDTO profilesDTO) throws ProfileServiceException {
        boolean isValidProfilesDTO = true;

        if (profilesDTO.getOffset() == 0 && profilesDTO.getLimit() == 0) {
            isValidProfilesDTO = false;
            logger.debug("Found offset and limit values 0 in profilesDTO {}.", profilesDTO);

            //TODO: throw rest layer exception when exception class is created in rest-api

            return isValidProfilesDTO;
        }

        if (profilesDTO.getFilter() != null) {
            
            isValidProfilesDTO = validateProfileFilterDTO(profilesDTO.getFilter());
        }

        return isValidProfilesDTO;
    }

}
