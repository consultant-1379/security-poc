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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

/**
 * This class will handle "TDPServiceResponse" response which will be consumed by the Listeners
 * 
 * @author tcsdemi
 *
 */
public class TDPSAcknowledgementEventSender {

    @Inject
    Logger logger;

    @Inject
    @Modeled
    private EventSender<TDPSAcknowledgementEvent> tDPSAcknowledgementEventSender;

    /**
     * This method is an Asynchronous method which will handle "TDPSAcknowledgementEvent" to persist all the CA and entity Certificates in DB.
     * 
     * @param tDPSAcknowledgementEvent
     *            Modeled event consisting of TDPSAcknowledgementEvent
     */
    public void send(final TDPSAcknowledgementEvent tDPSAcknowledgementEvent) {
        tDPSAcknowledgementEventSender.send(tDPSAcknowledgementEvent);

    }
}
