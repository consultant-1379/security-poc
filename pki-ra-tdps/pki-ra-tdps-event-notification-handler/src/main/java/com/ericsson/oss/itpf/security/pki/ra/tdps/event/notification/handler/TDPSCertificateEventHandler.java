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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.event.PublishTDPSCertificateEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.event.UnPublishTDPSCertficateEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * This class handles Modeled event "TDPSCertificateEvent" once it is consumed at the Listener.
 * 
 * @author tcsdemi
 *
 */
public class TDPSCertificateEventHandler {

    @Inject
    Logger logger;

    @Inject
    PublishTDPSCertificateEvent publishTDPSCertificateEvent;

    @Inject
    UnPublishTDPSCertficateEvent unPublishTDPSCertficateEvent;

    /**
     * This is an Asynchronous method which will handle either publishing or un-publishing of certificate i.e either to delete or persist onto TDPS database In case TdpsOperationType is PUBLISH,
     * certificate will be persisted into DB and in case of UNPUBLISH certificate will be deleted from database. There will be a warning logged in case there is any other operation type or in case it
     * is null
     * 
     * @param tDPSCertificateEvent
     */

    public void handle(final TDPSCertificateEvent tDPSCertificateEvent) {
        final String tDPSOperationTypeValue = tDPSCertificateEvent.getTdpsOperationType().toString();

        switch (tDPSCertificateEvent.getTdpsOperationType()) {

        case PUBLISH:
            publishTDPSCertificateEvent.execute(tDPSCertificateEvent);
            break;

        case UNPUBLISH:
            unPublishTDPSCertficateEvent.execute(tDPSCertificateEvent);
            break;

        default:
            if (tDPSCertificateEvent.getTdpsOperationType() != null) {
                logger.warn("Unknown TDPS Operation : {}", tDPSOperationTypeValue);
            } else {
                logger.warn("Unknown TDPS Operation : {}", tDPSCertificateEvent.getTdpsOperationType());
            }
        }

    }

}
