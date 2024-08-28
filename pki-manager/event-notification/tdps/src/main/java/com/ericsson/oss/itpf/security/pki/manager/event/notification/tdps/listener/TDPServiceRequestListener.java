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
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers.TDPSRequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceRequest;

/**
 * This class listens to TDPServiceRequest and delegates to TDPSRequestHandler which handled the request event
 * 
 * @author tcsdemi
 * 
 */
@ApplicationScoped
public class TDPServiceRequestListener {

    @Inject
    TDPSRequestHandler tdpsRequestHandler;

    @Inject
    Logger logger;

    public void listenForTDPServiceRequest(@Observes @Modeled final TDPServiceRequest tdpsServiceRequest) {
        try {
            logger.debug("Received TDPS request for retrieving all Active published certificates for CA and Entity");

            if (tdpsRequestHandler != null) {
                tdpsRequestHandler.handle();
            }
        } catch (Exception exception) {
            logger.error("Exception while processing the TDPS request in TDPServiceRequestListener " + exception.getMessage());
            logger.debug("caught exception while processing the TDPServiceRequest in TDPServiceRequestListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }
}