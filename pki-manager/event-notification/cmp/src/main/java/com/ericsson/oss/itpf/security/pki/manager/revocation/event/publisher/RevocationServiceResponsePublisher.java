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
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.publisher;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

/**
 * This class sends RevocationServiceResponse over the Modeled event bus. The request is sent to the CMP Service in PKI-Manager
 * 
 * @author tcsramc
 *
 */
public class RevocationServiceResponsePublisher {

    @Inject
    @Modeled
    private EventSender<SignedRevocationServiceResponse> signedRevocationServiceResponseSender;

    @Inject
    Logger logger;

    /**
     * This method send RevocationServiceResponse to PKI-RA service
     * 
     * @param signedRevocationServiceResponse
     *            Response that has to be sent over the modeled event bus to PKI-RA service.
     */
    public void publish(final SignedRevocationServiceResponse signedRevocationServiceResponse) {
        logger.info("Sending Revocation acknowledgement");

        signedRevocationServiceResponseSender.send(signedRevocationServiceResponse);
    }

}
