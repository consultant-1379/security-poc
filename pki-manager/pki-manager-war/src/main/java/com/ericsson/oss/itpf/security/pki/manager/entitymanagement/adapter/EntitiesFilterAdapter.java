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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.adapter;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityDTO;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityFilterDTO;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * A adapter class to convert the {@link EntityFilterDTO} and {@link EntityDTO} objects into API {@link EntitiesFilter} object.
 */
public class EntitiesFilterAdapter {

    /**
     * Converts the {@link EntityFilterDTO} to {@link EntitiesFilter} object
     *
     * @param entityFilterDTO
     *            EntityFilterDTO object containing filter conditions based on which entities has to be filtered.
     *
     * @return the {@link EntitiesFilter} Object containing id, type, name, certificateAssigned, active, inactive, offset and limit.
     *
     */
    public EntitiesFilter toEntitiesFilterForCount(final EntityFilterDTO entityFilterDTO) {
        EntitiesFilter entitiesFilter = new EntitiesFilter();

        if (!ValidationUtils.isNullOrEmpty(entityFilterDTO.getType())) {
            entitiesFilter = fillFilterDTO(entitiesFilter, entityFilterDTO);
        }

        return entitiesFilter;
    }

    /**
     * Converts the {@link EntityDTO} to {@link EntitiesFilter} object
     *
     * @param entityDTO
     *            EntityDTO object specifying filter conditions, offset and limit based on which entities has to be filtered.
     *
     * @return the {@link EntitiesFilter} Object containing id, type, name, certificateAssigned, active, inactive, offset and limit.
     *
     */
    public EntitiesFilter toEntitiesFilterForFetch(final EntityDTO entityDTO) {
        EntitiesFilter entitiesFilter = new EntitiesFilter();
        EntityFilterDTO entityFilterDTO = null;

        if (entityDTO != null) {
            entityFilterDTO = entityDTO.getFilter();

            entitiesFilter.setId(entityDTO.getId());
            entitiesFilter.setOffset(entityDTO.getOffset());
            entitiesFilter.setLimit(entityDTO.getLimit());
        }

        if (entityFilterDTO != null) {
            entitiesFilter = fillFilterDTO(entitiesFilter, entityFilterDTO);
        }

        return entitiesFilter;
    }

    private EntitiesFilter fillFilterDTO(final EntitiesFilter entitiesFilter, final EntityFilterDTO entityFilterDTO) {
        if (entityFilterDTO != null) {
         
            entitiesFilter.setCertificateAssigned(entityFilterDTO.getCertificateAssigned());
            entitiesFilter.setName(entityFilterDTO.getName());
            entitiesFilter.setType(entityFilterDTO.getType());
            entitiesFilter.setStatus(entityFilterDTO.getStatus());
        }
        
        if((entitiesFilter.getStatus().size() == 1 && entitiesFilter.getStatus().contains(EntityStatus.REISSUE)) 
                && entitiesFilter.getType().contains(EntityType.CA_ENTITY)  ){
            entitiesFilter.getType().remove(EntityType.CA_ENTITY);
        }

        return entitiesFilter;
    }
}
