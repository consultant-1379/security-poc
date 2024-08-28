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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers.TDPSAcknowledgementRequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

/**
 * This is a listener class which listens to TDPSAcknowledgment event
 * 
 * @author tcsdemi
 * 
 */
@ApplicationScoped
public class TDPSAcknowledgementRequestListener {
    @Inject
    TDPSAcknowledgementRequestHandler tDPSAcknowledgementRequestHandler;

    @Inject
    Logger logger;

    public void listenForTDPSAcknowledgementEvent(@Observes @Modeled final TDPSAcknowledgementEvent tdpsAcknowledgementEvent) {
        try {
            logger.debug("Received TDPS tdpsAcknowledgementEvent request for retrieving all Active published certificates for CA and Entity");

            if (tdpsAcknowledgementEvent != null) {
                tDPSAcknowledgementRequestHandler.handle(tdpsAcknowledgementEvent);
            }
        } catch (Exception exception) {
            logger.error("Error occured while updating the TDPS Acknowledgement Status in TDPSAcknowledgementRequestListener " + exception.getMessage());
            logger.debug("caught exception while processing the TDPSAcknowledgementEvent in TDPSAcknowledgementRequestListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }
}