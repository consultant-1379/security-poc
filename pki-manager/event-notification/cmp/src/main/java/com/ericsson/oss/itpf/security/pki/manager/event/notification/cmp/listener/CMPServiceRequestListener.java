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
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.CMPServiceRequest;

@ApplicationScoped
public class CMPServiceRequestListener {

    @Inject
    Logger logger;

    /**
     * This method listens for CMPServiceRequest over the Modeled event bus.
     * 
     * @param CMPServiceRequest
     *            The CMP request for certificate generation of end entity
     */
    public void listenToRequest(@Observes @Modeled final CMPServiceRequest CMPServiceRequest) {
        logger.error("Received CMP Request is not signed,Invalid CMPService Request Sent from PKI-RA");

    }

}
