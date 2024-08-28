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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

/**
 * This mapper class is used to map TDPSEntityType (EDT) to TDPSEntity application level ENUM and vice versa
 * 
 * @author xdeemin
 *
 */
public class TDPSEntityTypeMapper {

    /**
     * This method converts TDPSEntityType,model attribute EDT to TDPSEntity ENUM
     * 
     * @param tdpsEntityType
     *            is an EDT which can have values as ENTITY,CA_ENTITY
     * @return
     */
    public TDPSEntity fromModel(final TDPSEntityType tdpsEntityType) {
        TDPSEntity entityType = null;

        switch (tdpsEntityType) {
        case ENTITY: {
            entityType = TDPSEntity.ENTITY;
            break;
        }
        case CA_ENTITY: {
            entityType = TDPSEntity.CA_ENTITY;
            break;
        }
        default: {
            entityType = TDPSEntity.UNKNOWN;
            break;
        }
        }

        return entityType;
    }

    /**
     * This method is used to convert TDPSEntity ENUM to TDPSEntityType EDT
     * 
     * @param entityType
     *            is an ENUM which can have ENTITY,CA_ENTITY
     * @return
     */
    public TDPSEntityType toModel(final TDPSEntity entityType) {
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
            break;
        }
        }

        return tdpsEntityType;
    }

}
