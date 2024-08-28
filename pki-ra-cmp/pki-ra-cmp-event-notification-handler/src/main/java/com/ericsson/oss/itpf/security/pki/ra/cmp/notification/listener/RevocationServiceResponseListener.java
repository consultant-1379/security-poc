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
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.RevocationServiceResponseEvent;

@ApplicationScoped
public class RevocationServiceResponseListener {

    @Inject
    Logger logger;

    /**
     * This is a listener which observes and consumes CMPServ iceResponse modeled event and delegates asynchronously to PKIManagerCMPResponseHandler for further handling
     * 
     * @param signedCMPServiceResponse
     *            It is a modeled event which will be received over the modeled event bus which will contain responseType/ResponseBytes/TransactionId
     */
    void listenToResponse(@Observes @Modeled final RevocationServiceResponseEvent revocationServiceResponse) {

        logger.error("Received Revocation Response is not signed.So, the Response Message Sent by Manager is invalid.");

    }

}
