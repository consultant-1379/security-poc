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
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPServiceResponseEventBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender.TDPServiceResponseEventSender;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.TrustDistributionLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * This class is used to handle TDPSServiceRequest wherein all the published certificates for Entity and CA entity are fetched fro Manager DB and sent to pki-ra-tdps over the Modeled event bus.
 * 
 * @author tcsdemi
 *
 */
public class TDPSRequestHandler {

    @EJB
    TrustDistributionLocalService trustDistributionLocalService;

    @Inject
    TDPServiceResponseEventSender tdpServiceResponseEventSenderForEntity;

    @Inject
    TDPServiceResponseEventSender tdpServiceResponseEventSenderForCAEntity;

    @Inject
    Logger logger;

    /**
     * This method handles TDPSErviceRequest wherein published certificates are fetched and sent over the queue.
     * 
     */
    public void handle() {
        try {
            final TDPServiceResponse tDPServiceResponseForEntityCertificates = buildTDPServiceResponse(EntityType.ENTITY);
            tdpServiceResponseEventSenderForEntity.send(tDPServiceResponseForEntityCertificates);

            final TDPServiceResponse tDPServiceResponseForCACertificates = buildTDPServiceResponse(EntityType.CA_ENTITY);
            tdpServiceResponseEventSenderForCAEntity.send(tDPServiceResponseForCACertificates);
        } catch (Exception exception) {
            handleException(exception);
        }
    }

    private TDPServiceResponse buildTDPServiceResponse(final EntityType entityType) throws CertificateException, PersistenceException, IOException {
        final Map<String, List<Certificate>> tDPSCertificates = trustDistributionLocalService.getPublishedCertificates(entityType);

        final TDPSEntityType tDPSEntityType = (entityType == EntityType.CA_ENTITY) ? TDPSEntityType.CA_ENTITY : TDPSEntityType.ENTITY;
        return generateTDPSServiceResponse(tDPSEntityType, tDPSCertificates);
    }

    private TDPServiceResponse generateTDPSServiceResponse(final TDPSEntityType tDPSEntityType, final Map<String, List<Certificate>> tDPSCertificateMap) {
        final TDPServiceResponseEventBuilder tDPServiceResponseEventBuilder = new TDPServiceResponseEventBuilder().trustMap(tDPSCertificateMap).entityType(tDPSEntityType);
        final TDPServiceResponse tDPServiceResponse = tDPServiceResponseEventBuilder.build();

        return tDPServiceResponse;
    }

    private void handleException(final Throwable cause) {
        logger.debug("Exception StackTrace: ", cause);
        logger.warn("Error Occured while retriving certificates, not sending any response to pki-ra-tdps");
    }
}