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

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.model.TDPSAcknowledgementStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

/**
 * This is a mapper class which converts TDPSResponse type to AcknowledgmentStatus i.e whether certificate is published or not.
 * 
 * @author tcsdemi
 *
 */
public class TDPSResponseTypeMapper {

    @Inject
    Logger logger;

    /**
     * This method converts model object TDPSResponseType to TDPSAcknowledgementStatus
     * 
     * @param tdpsResponseType
     * @return
     */
    public TDPSAcknowledgementStatus fromModel(final TDPSResponseType tdpsResponseType) {
        TDPSAcknowledgementStatus tDPSAcknowledgementStatus = null;

        switch (tdpsResponseType) {
        case SUCCESS: {
            tDPSAcknowledgementStatus = TDPSAcknowledgementStatus.SUCCESS;
            break;
        }
        case FAILURE: {
            tDPSAcknowledgementStatus = TDPSAcknowledgementStatus.FAILURE;
            break;
        }
        default:
            logger.warn("Unknown acknowledgment status received from Model");
            break;
        }
        return tDPSAcknowledgementStatus;
    }
}