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

package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import java.util.EnumSet;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class used for Certificates Filter to decide {@link EntityType} like CA_ENTITY/ENTITY/CAANDENTITY
 */
public enum EntityTypeFilter {
    CAANDENTITY(EnumSet.of(EntityType.CA_ENTITY, EntityType.ENTITY));

    EnumSet<EntityType> entityTypeSet;

    private EntityTypeFilter(final EnumSet<EntityType> entityTypeSet) {
        this.entityTypeSet = entityTypeSet;
    }

    public EnumSet<EntityType> getEntityTypeSet() {
        return entityTypeSet;
    }

    /**
     * check and return Entity Type
     *
     * @param entityTypes
     *            {@link EntityType} array
     * @return return EnumSet has CA_ENTITY/ENTITY/CAANDENTITY.
     */
    public static EnumSet<EntityType> getEntityType(final EntityType[] entityTypes) {

        if (entityTypes == null || entityTypes.length == 0 || entityTypes.length == 2) {
            return EntityTypeFilter.CAANDENTITY.getEntityTypeSet();
        }
        if (entityTypes[0] == EntityType.CA_ENTITY) {
            return EnumSet.of(EntityType.CA_ENTITY);
        } else {
            return EnumSet.of(EntityType.ENTITY);
        }
    }
}
