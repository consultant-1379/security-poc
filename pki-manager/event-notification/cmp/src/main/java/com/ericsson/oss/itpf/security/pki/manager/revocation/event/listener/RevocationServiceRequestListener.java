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
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.RevocationServiceRequestEvent;

/**
 * This class listens for the RevocationServiceRequest over the Modeled event bus. The request is being received from pkiraservice.
 * 
 * @author tcsramc
 * 
 */
@ApplicationScoped
public class RevocationServiceRequestListener {

    @Inject
    private Logger logger;

    /**
     * Listens to the RevocationServiceRequest from the PKI-RA Service
     * 
     * @param revocationServiceRequest
     *            request which comes from pki-ra over modeled event bus.
     */
    public void listen(@Observes @Modeled final RevocationServiceRequestEvent revocationServiceRequest) {
        logger.error("Received Revocation Request is not signed.So, the Revocation Request Message Sent by CMP is invalid.");
    }
}
