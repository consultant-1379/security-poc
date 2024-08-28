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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler.TDPSCertificateEventHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * This class is a listener for "TDPSCertificateEvent"
 * 
 * @author tcsdemi
 * 
 */
@ApplicationScoped
public class TDPServiceCertificateEventListener {

    @Inject
    TDPSCertificateEventHandler tDPSCertificateEventHandler;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    public void listenForCertificateEvent(@Observes @Modeled final TDPSCertificateEvent tdpsCertificateEventResponse) {

        try {
            final String operationType = tdpsCertificateEventResponse.getTdpsOperationType().name();
            logger.info("Received CertificateEvent from PKI-Manager for the Event {}", operationType);
            if (tdpsCertificateEventResponse.getTdpsCertificateInfos() != null) {
                tDPSCertificateEventHandler.handle(tdpsCertificateEventResponse);
            } else {
                systemRecorder.recordError("TDPS_SERVICE.CERTIFICATE_INFO_NOT_FOUND", ErrorSeverity.ERROR, operationType + " of certificate",
                        "Trusted Certificates of Entity which invokes TDPS", "CertificateInfo is NULL from the TDPSCertificateEvent");
                logger.error("Certificate Event does not contain any valid Data i.e CertificateInfo is NULL");
            }
        } catch (Exception exception) {
            logger.error("Exception found while publishing/Unpublishing Certificates in TDPS in TDPServiceCertificateEventListener {} " , exception.getMessage());
            logger.debug("Caught exception while publishing/Unpublishing Certificates in TDPServiceCertificateEventListener {} ", exception.getMessage(), exception);
            throw exception;
        }
    }
}
