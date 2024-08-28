/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityExportMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityExportMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 *
 * Model Mapper Factory used to get the instance of proper Entities Mapper out of CAENtity/Entity Mappers.
 *
 * @author zkakven
 *
 */
public class EntitiesModelMapperFactoryv1 {

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    ModelMapperv1 caEntityModelMapper;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    ModelMapperv1 entityModelMapper;

    @Inject
    CAEntityExportMapper caEntityExportMapper;

    @Inject
    EntityExportMapper entityExportMapper;

    /**
     * The method to get the appropriate {@link ModelMapper} instance based on {@link EntityType}.
     *
     * @param entityType
     * @return Instance of {@link ModelMapper}
     */
    public ModelMapperv1 getEntitiesMapper(final EntityType entityType) throws InvalidEntityException {
        ModelMapperv1 modelMapper = null;

        switch (entityType) {
        case CA_ENTITY:
            modelMapper = caEntityModelMapper;
            break;

        case ENTITY:
            modelMapper = entityModelMapper;
            break;

        default:
            throw new InvalidEntityException(ProfileServiceErrorCodes.INVALID_ENTITY_TYPE);
        }

        return modelMapper;
    }

    /**
     * This method returns the appropriate {@link ModelMapper} used for import/update entity operation based on {@link EntityType}.
     *
     * @param entityType
     *            type of the Entity
     * @return Instance of {@link ModelMapper}
     * @throws InvalidEntityException
     *             thrown when invalid EntityType is provided.
     */
    public ModelMapper getEntitiesExportMapper(final EntityType entityType) throws InvalidEntityException {
        ModelMapper modelMapper = null;

        switch (entityType) {
        case CA_ENTITY:
            modelMapper = caEntityExportMapper;
            break;

        case ENTITY:
            modelMapper = entityExportMapper;
            break;

        default:
            throw new InvalidEntityException(ProfileServiceErrorCodes.INVALID_ENTITY_TYPE);
        }

        return modelMapper;
    }

}