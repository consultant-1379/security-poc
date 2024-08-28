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

import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;

/**
 * This class is used to extract entity name from the given entity.
 * 
 * @author tcsramc
 *
 */
public class EntityNameUtils {
    private EntityNameUtils() {

    }

    /**
     * This method returns entity name from the given entity.
     * 
     * @param abstractEntity
     *            for which entity name has to return.
     * @return returns entity name.
     */
    public static <T extends AbstractEntity> String getName(final T abstractEntity) {

        final EntityType entityType = abstractEntity.getType();
        String entityName = null;

        switch (entityType) {

        case ENTITY:
            entityName = ((Entity) abstractEntity).getEntityInfo().getName();
            break;

        case CA_ENTITY:
            entityName = ((CAEntity) abstractEntity).getCertificateAuthority().getName();
            break;

        }

        return entityName;

    }

}
