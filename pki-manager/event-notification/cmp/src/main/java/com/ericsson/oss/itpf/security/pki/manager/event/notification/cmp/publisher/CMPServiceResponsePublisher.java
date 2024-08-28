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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;

/**
 * @author tcsswpa This class sends CMPServiceResponse over the Modeled event bus. The request is sent to the CMP Service in PKI-Manager
 */
public class CMPServiceResponsePublisher {

    @Inject
    Logger logger;
    
    @Inject
    @Modeled
    private EventSender<SignedCMPServiceResponse> cMPServiceResponseEventSender;

    /**
     * This method dispatches for CMPServiceResponse over the Modeled event bus.
     * 
     * @param signedCMPServiceResponse
     *            The CMP response message containing the end entity certificate and trusted certificates
     */

    public void publish(final SignedCMPServiceResponse signedCMPServiceResponse) {

        logger.info("Publishing signedCMPServiceResponse Message in ClusteredCMPServiceResponseChannel");
        cMPServiceResponseEventSender.send(signedCMPServiceResponse);
    }

}