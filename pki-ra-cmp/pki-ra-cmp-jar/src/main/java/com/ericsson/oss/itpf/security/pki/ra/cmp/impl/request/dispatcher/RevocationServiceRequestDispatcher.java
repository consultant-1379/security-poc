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
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;

public class RevocationServiceRequestDispatcher {

    @Inject
    @Modeled
    private EventSender<SignedRevocationServiceRequest> signedRevocationServiceRequestSender;

    @Inject
    Logger logger;

    /**
     * This method sends Revocation Service Request over the modeled event bus to PKI-manager.
     * 
     * @param signedRevocationServiceRequest
     *            to be sent over Event bus
     */
    public void dispatch(final SignedRevocationServiceRequest signedRevocationServiceRequest) {
        logger.info("Sending Revocation request to PKI-Manager");
        signedRevocationServiceRequestSender.send(signedRevocationServiceRequest);

    }

}
