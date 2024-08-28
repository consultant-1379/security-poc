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
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler.TDPServiceResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * This class is a Listener for "TDPServiceResponse"
 * 
 * @author tcsdemi
 * 
 */
@ApplicationScoped
public class TDPServiceResponseEventListener {

    @Inject
    TDPServiceResponseHandler tDPSResponseHandler;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    public void listenForTDPServiceResponse(@Observes @Modeled final TDPServiceResponse tDPSServiceResponse) {
        try {
            logger.info("Received TDPService Response from PKI-Manager");
            if (tDPSServiceResponse.getTdpsCertificateInfoList() != null) {
                tDPSResponseHandler.handle(tDPSServiceResponse);
            } else {
                systemRecorder.recordError("TDPS_SERVICE.PUBLISH_EVENT_FAILED", ErrorSeverity.ERROR, "Publish Certificates to TDPS",
                        "Trusted Certificates of Entity which invokes TDPS", "No Certificate Info obtained from TDPServiceResponse");
                logger.error("Received TDPSServiceResponse with empty CertificateInfoList. ");
            }
        } catch (Exception exception) {
            logger.error("Exception found while handling the TDPServiceResponse in TDPServiceResponseEventListener {} " , exception.getMessage());
            logger.debug("Caught exception while handling the TDPServiceRespons in TDPServiceResponseEventListener {} ", exception.getMessage(), exception);
            throw exception;
        }

    }
}
