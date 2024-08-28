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
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.manager.revocation.event.handler.RevocationServiceRequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;

/**
 * This class listens for the RevocationServiceRequest over the Modeled event bus. The request is being received from pkiraservice.
 * 
 * @author tcsramc
 * 
 */
@ApplicationScoped
public class SignedRevocationServiceRequestListener {

    @Inject
    private RevocationServiceRequestHandler revocationRequestProcessor;

    @Inject
    private Logger logger;

    /**
     * Listens to the RevocationServiceRequest from the PKI-RA Service
     * 
     * @param signedRevocationServiceRequest
     *            request which comes from pki-ra over modeled event bus.
     */
    public void listen(@Observes @Modeled final SignedRevocationServiceRequest signedRevocationServiceRequest) {
        try {
            logger.debug("receiveGetCrlRequestMessage of CRLRequestMessageListener class");
            revocationRequestProcessor.handle(signedRevocationServiceRequest);
        } catch (Exception exception) {
            logger.error("Exception occured while handling the revocation request from cmp in SignedRevocationServiceRequestListener " + exception.getMessage());
            logger.debug("caught exception while processing the SignedRevocationServiceRequest in SignedRevocationServiceRequestListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }
}