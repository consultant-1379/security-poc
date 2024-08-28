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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * This class is used to send TDPSCertificateEvent over the queue
 * 
 * @author tcsdemi
 *
 */
public class TDPSCertificateEventSender {

    @Inject
    @Modeled
    private EventSender<TDPSCertificateEvent> tDPSCertificateEventSender;

    /**
     * This method sends TDPSCertificateEvent over the queue using EventSender<TDPSCertificateEvent>
     * 
     * @param tdpsCertificateEvent
     */
    public void send(final TDPSCertificateEvent tdpsCertificateEvent) {
        tDPSCertificateEventSender.send(tdpsCertificateEvent);
    }
}