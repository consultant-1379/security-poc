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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

/**
 * This is a mapper class which is used to convert EntityType to TDPSEntityType
 * 
 * @author tcsdemi
 *
 */
public class TDPSEntityTypeMapper {

    @Inject
    Logger logger;

    /**
     * This method converts EntityType to TDPSEntityType
     * 
     * @param entityType
     * @return
     */
    public TDPSEntityType toModel(final EntityType entityType) {
        TDPSEntityType tdpsEntityType = null;

        switch (entityType) {
        case ENTITY: {
            tdpsEntityType = TDPSEntityType.ENTITY;
            break;
        }
        case CA_ENTITY: {
            tdpsEntityType = TDPSEntityType.CA_ENTITY;
            break;

        }
        default: {
            tdpsEntityType = TDPSEntityType.UNKNOWN_ENTITY;
        }
        }
        return tdpsEntityType;
    }

    /**
     * This method converts TDPSEntityType to EntityType
     * 
     * @param tdpsEntityType
     * @return
     */
    public EntityType fromModel(final TDPSEntityType tdpsEntityType) {
        EntityType entityType = null;
        switch (tdpsEntityType) {
        case ENTITY: {
            entityType = EntityType.ENTITY;
            break;
        }
        case CA_ENTITY: {
            entityType = EntityType.CA_ENTITY;
            break;

        }
        default: {
            logger.warn("Unknwon entitytype received from Model");
            break;
        }
        }

        return entityType;
    }

}
