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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.processor.CMPServiceRequestProcessor;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceRequest;

/**
 * @author tcsswpa This class listens for the CMPServiceRequest over the Modeled event bus. The request is being received from pkiraservice.
 */

@ApplicationScoped
public class SignedCMPServiceRequestListener {

    @Inject
    CMPServiceRequestProcessor cmpServiceRequestProcessor;

    @Inject
    Logger logger;

    /**
     * This method listens for CMPServiceRequest over the Modeled event bus.
     * 
     * @param signedCMPServiceRequest
     *            The CMP request for certificate generation of end entity
     */
    public void listenToRequest(@Observes @Modeled final SignedCMPServiceRequest signedCMPServiceRequest) {

        logger.info("Received Signed CMP Modeled event request from pkira cmp service.");
        try {
            cmpServiceRequestProcessor.processRequest(signedCMPServiceRequest);
        } catch (Exception exception) {
            logger.error("Error in processing the request sent from CMP in SignedCMPServiceRequestListener " + exception.getMessage());
            logger.debug("caught exception while processing the SignedCMPServiceRequest in SignedCMPServiceRequestListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }

}