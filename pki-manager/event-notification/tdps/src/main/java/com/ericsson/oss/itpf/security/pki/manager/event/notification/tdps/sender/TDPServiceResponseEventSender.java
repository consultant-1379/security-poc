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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * This class is ServiceResponseEvent sender which sends TDPServiceResponse over the modeled event bus.
 * 
 * @author tcsdemi
 *
 */
public class TDPServiceResponseEventSender {

    @Inject
    @Modeled
    private EventSender<TDPServiceResponse> trustDistributionServiceResponseEventSender;

    public void send(final TDPServiceResponse tdpServiceResponse) {
        trustDistributionServiceResponseEventSender.send(tdpServiceResponse);
    }
}