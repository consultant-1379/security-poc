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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationRequestMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.handler.CRLNotificationRequestMessageHandler;

/**
 * CRLNotificationRequestMessageListener will listen the CRLNotificationRequestMessage.
 * 
 * @author xvambur
 * 
 */
@ApplicationScoped
public class CRLNotificationRequestMessageListener {

    @Inject
    private CRLNotificationRequestMessageHandler crlNotificationRequestMessageHandler;

    @Inject
    private Logger logger;

    /**
     * This method will listen the CRLNotificationRequestMessage. Upon receiving the message from CDPS, manager will send CRL Publish and Unpublish Notification Messages to CDPS
     * 
     * @param crlNotificationRequestMessage
     *            - Crl Notification Request message
     */
    public void receiveCRLNotificationReqMessage(@Observes @Modeled final CRLNotificationRequestMessage crlNotificationRequestMessage) {
        try {
            logger.debug("receiveCRLNotificationRequestMessage of CRLNotificationRequestMessageListener class");

            crlNotificationRequestMessageHandler.handle();

            logger.debug("End of method receiveCRLNotificationRequestMessage of CRLNotificationRequestMessageListener class");
        } catch (Exception exception) {
            logger.error("Exception found while handling publish/unpublish crls request in CRLNotificationRequestMessageListener " + exception.getMessage());
            logger.debug("caught exception while processing the CRLNotificationRequestMessage in CRLNotificationRequestMessageListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }
}
