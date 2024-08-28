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
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceRequest;

/**
 * This is a startup EJB service which publishes an event to PKI-Manager in order to fetch all certificates which are Active and with published flag as true. TDPServiceRequestSender is a no attribute
 * event. This event need not have any attributes for filtering certificates at PKI-Manager,since all certificates needs to be retrieved.
 * 
 * This service consists of one PostConstruct callback method which publishes event to EventBus.
 * 
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.request.sender.TDPServiceRequestSender
 * 
 * @author tcsdemi
 *
 */
@Singleton
@Startup
public class TrustDistributionPointServiceStartupBean {

    @Inject
    @Modeled
    private EventSender<TDPServiceRequest> tDPSServiceRequestEventSender;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @PostConstruct
    public void onServiceStart() {
        logger.info("Publishing initial event for fetching all published and active certificates");
        try {
            final TDPServiceRequest tDPSServiceRequest = new TDPServiceRequest();
            tDPSServiceRequestEventSender.send(tDPSServiceRequest);

        } catch (Exception exception) {
            logger.info("Failed sending startUp request to fetch all the entity and CA entity certificates to TDPS from PKI Manager");
            logger.error("Sending of startUp request to fetch all the entity and CA entity certificates to TDPS from PKI Manager is Failed due to {}", exception.getMessage());
            logger.debug("Sending of startUp request to fetch all the entity and CA entity certificates to TDPS from PKI Manager is Failed due to {}", exception);
            systemRecorder.recordError("PKIRASERVICE.TIMERSERVICE_FAILED", ErrorSeverity.ERROR, "PKIRA.TrustDistributionPointServiceStartup", "PUBLISH_CERTIFICATE_TO_TDPS",
                    "Sending of startUp request to fetch all the entity and CA entity certificates to TDPS from PKI Manager is Failed due to " + exception.getMessage());
        }
        logger.info("End of onServiceStart method in TrustDistributionPointServiceStartupBean");
        systemRecorder.recordEvent("PKIRASERVICE.TIMERSERVICE", EventLevel.COARSE, "PKIRA.TrustDistributionPointServiceStartup", "PUBLISH_CERTIFICATE_TO_TDPS",
                "Published an event to PKI-Manager to fetch all certificates which are Active and with published flag as true");
    }
}
