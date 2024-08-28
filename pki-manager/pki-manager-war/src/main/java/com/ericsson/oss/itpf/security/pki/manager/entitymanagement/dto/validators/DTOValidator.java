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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.validators;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class validates all the values given in DTO's {@link EntityDTO} , {@link EntityFilterDTO}.
 *
 */
public class DTOValidator {

    @Inject
    private Logger logger;

    /**
     * This method validates the entity filter DTO attributes given as input
     *
     * @param entityFilterDTO
     *            EntityFilterDTO object containing filter conditions based on which entities has to be filtered.
     * @return boolean returns true if all the attributes are valid or else false
     *
     */
    public boolean validateEntityFilterDTO(final EntityFilterDTO entityFilterDTO) {
        boolean isValidEntityFilterDTO = true;

        if (entityFilterDTO.getType() == null && entityFilterDTO.getName() == null && entityFilterDTO.getCertificateAssigned() == null && entityFilterDTO.getStatus() == null) {
            isValidEntityFilterDTO = true;
            return isValidEntityFilterDTO;
        }

        if (ValidationUtils.isNullOrEmpty(entityFilterDTO.getType())) {
            isValidEntityFilterDTO = false;
            return isValidEntityFilterDTO;
        }

        if (entityFilterDTO.getName() == null) {
            isValidEntityFilterDTO = false;
            return isValidEntityFilterDTO;
        }
        if (ValidationUtils.isNullOrEmpty(entityFilterDTO.getStatus())) {
            isValidEntityFilterDTO = false;
            return isValidEntityFilterDTO;
        }
        if ((entityFilterDTO.getStatus().size() == 1 && entityFilterDTO.getStatus().contains(EntityStatus.REISSUE)) && entityFilterDTO.getType().size() == 1
                && entityFilterDTO.getType().contains(EntityType.CA_ENTITY)) {
            isValidEntityFilterDTO = false;
            return isValidEntityFilterDTO;
        }

        return isValidEntityFilterDTO;
    }

    /**
     * This method validates the entity DTO attributes given as input
     *
     * @param entityDTO
     *            EntityDTO object specifying filter conditions, offset and limit based on which entities has to be filtered
     * @return boolean returns true if all the attributes are valid or else false
     *
     */
    public boolean validateEntityDTO(final EntityDTO entityDTO) throws EntityServiceException {
        boolean isValidEntityDTO = true;

        if (entityDTO.getOffset() == 0 && entityDTO.getLimit() == 0) {
            isValidEntityDTO = false;
            logger.info("Found offset and limit values 0 in entityDTO {}.", entityDTO);

            //TODO: throw rest layer exception when exception class is created in rest-api

            return isValidEntityDTO;
        }

        if (entityDTO.getFilter() != null) {
            isValidEntityDTO = validateEntityFilterDTO(entityDTO.getFilter());
        }

        return isValidEntityDTO;
    }
}
