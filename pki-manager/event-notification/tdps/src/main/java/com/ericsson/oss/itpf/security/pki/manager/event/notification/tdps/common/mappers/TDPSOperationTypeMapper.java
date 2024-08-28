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

import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;

/**
 * This class is a mapper class which converts TDPSPublishStatusType to TDPSOperationType and vice versa
 * <p>
 * TDPSPublishStatusType - is an ENUM class
 * <p>
 * TDPSOperationType - is an Emodel EDT class
 * 
 * @author tcsdemi
 *
 */
public class TDPSOperationTypeMapper {

    /**
     * This method is used to map TDPSPublishStatusType to TDPSOperationType (which is an EMODEL)
     * 
     * @param tdpsPublishStatusType
     * @return
     */
    public TDPSOperationType toModel(final TDPSPublishStatusType tdpsPublishStatusType) {
        TDPSOperationType tdpsOperationType = null;
        switch (tdpsPublishStatusType) {
        case PUBLISH: {
            tdpsOperationType = TDPSOperationType.PUBLISH;
            break;
        }
        case UNPUBLISH: {
            tdpsOperationType = TDPSOperationType.UNPUBLISH;
            break;
        }
        default: {
            tdpsOperationType = TDPSOperationType.UNKNOWN;
        }
        }
        
        return tdpsOperationType;
    }

    /**
     * This methos is used to map TDPSOperationType(EMODEL) to local ENUM TDPSPublishStatusType
     * 
     * @param tdpsOperationType
     * @return
     */
    public TDPSPublishStatusType fromModel(final TDPSOperationType tdpsOperationType) {
        TDPSPublishStatusType tdpsPublishStatusType = null;

        switch (tdpsOperationType) {
        case PUBLISH: {
            tdpsPublishStatusType = TDPSPublishStatusType.PUBLISH;
            break;
        }
        case UNPUBLISH: {
            tdpsPublishStatusType = TDPSPublishStatusType.UNPUBLISH;
            break;
        }
        default: {
            tdpsPublishStatusType = TDPSPublishStatusType.UNKNOWN;
        }
        }
        
        return tdpsPublishStatusType;
    }
}