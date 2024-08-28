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
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.handler.RevocationServiceResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

/**
 * This is a listener class which consumes modeled event <code>RevocationServiceResponse</code> and delegates this response from modeled event bus to<code>RevocationServiceResponseHandler</code> for
 * handling.
 *
 * @author tcsramc
 *
 */
@ApplicationScoped
public class SignedRevocationServiceResponseListener {

    @Inject
    RevocationServiceResponseHandler revocationServiceResponseHandler;

    @Inject
    Logger logger;

    /**
     * This is a listener which observes and consumes RevocationServiceResponse modeled event and delegates asynchronously to RevocationServiceResponseHandler for further handling
     *
     * @param RevocationServiceResponseEvent
     *            It is a modeled event which will be received over the modeled event bus which will contain isvalid/issuerName/TransactionId
     */
    void listenForRevocationServiceResponse(@Observes @Modeled final SignedRevocationServiceResponse signedRevocationServiceResponse) {
        try {
            revocationServiceResponseHandler.handle(signedRevocationServiceResponse);
        } catch (Exception exception) {
            logger.error("Exception occurred while updating the revocation details at cmp in SignedRevocationServiceResponseListener: {}", exception.getMessage());
            logger.debug("caught exception while processing the SignedRevocationServiceResponse in SignedRevocationServiceResponseListener: {}", exception);
            throw exception;
        }
    }

}
