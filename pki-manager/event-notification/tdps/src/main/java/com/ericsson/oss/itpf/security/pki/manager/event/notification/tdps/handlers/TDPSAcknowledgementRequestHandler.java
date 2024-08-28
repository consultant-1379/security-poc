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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers;

import java.io.IOException;
import java.security.cert.CertificateException;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSEntityTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSResponseTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.TrustDistributionLocalService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

/**
 * This class is used to handle AcknowledgementRequest from pki-ra-tdps which in turn is used for updating Certificate status whether it is published or not in TDPS
 * 
 * @author tcsdemi
 *
 */
public class TDPSAcknowledgementRequestHandler {

    @Inject
    TDPSResponseTypeMapper tDPSResponseTypeMapper;

    @Inject
    TDPSEntityTypeMapper tDPSEntityTypeMapper;

    @EJB
    TrustDistributionLocalService trustDistributionLocalService;

    @Inject
    Logger logger;

    /**
     * This method is used to handle acknowledgementEvent from pki-ra-tdps. In this method CertificateData table is updated whether a certificate of a particular serialNumber issued by a CA is
     * published or not.
     */
    public void handle(final TDPSAcknowledgementEvent tdpsAcknowledgementEvent) {

        if (tdpsAcknowledgementEvent.getResponseType() == TDPSResponseType.SUCCESS) {
           final boolean operationType = (tdpsAcknowledgementEvent.getTdpsOperationType() == TDPSOperationType.PUBLISH) ? true : false;

            for (final TDPSCertificateInfo tdpsCertificateInfo : tdpsAcknowledgementEvent.getTdpsCertificateInfoList()) {
                try {
                    trustDistributionLocalService.updateCertificateStatus(tDPSEntityTypeMapper.fromModel(tdpsCertificateInfo.getTdpsEntityType()), tdpsCertificateInfo.getEntityName(),
                            tdpsCertificateInfo.getIssuerName(), tdpsCertificateInfo.getSerialNumber(), operationType);
                } catch (CertificateException | EntityNotFoundException | IOException | PersistenceException exception) {
                    logger.debug("Exception stacktrace", exception);
                } catch (final Exception exception) {
                    logger.debug("Error occured while updating the TDPS Acknowledgement Status: ", exception.getMessage(), exception);
                }
            }
        } else {
            final String tdpsAcknowledgementEventResponseType = tdpsAcknowledgementEvent.getResponseType().toString();
            logger.info("Negative acknowledgement for TDPS due to {} ", tdpsAcknowledgementEventResponseType);
            logger.warn("Certificate flag for PUBLISHED_TO_FLAG is not updated and will remain as before ");
        }
    }
}