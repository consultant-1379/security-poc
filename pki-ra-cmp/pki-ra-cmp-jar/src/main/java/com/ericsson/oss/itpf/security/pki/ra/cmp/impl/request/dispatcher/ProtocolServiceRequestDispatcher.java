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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.dispatcher;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceRequest;

/**
 * This class sends CMP RequestMessage onto modeled event bus.
 * <p>
 * Method:<code> sendCMPRequestMessage(final RequestMessage pKIRequestMessage, final String transactionID)</code>
 * 
 * @author tcsdemi
 *
 */
public class ProtocolServiceRequestDispatcher {

    @Inject
    @Modeled
    private EventSender<SignedCMPServiceRequest> signedCMPServiceRequestEventSender;

    @Inject
    Logger logger;

    /**
     * This method sends requestMessage over the modeled event bus
     * 
     * @param signedCMPServiceRequest
     *            request which has to be sent to PKI-Manager.
     */
    public void dispatch(final SignedCMPServiceRequest signedCMPServiceRequest) {

        signedCMPServiceRequestEventSender.send(signedCMPServiceRequest); // using default destination, priority, TTL from model, attaches all filters

    }

}
