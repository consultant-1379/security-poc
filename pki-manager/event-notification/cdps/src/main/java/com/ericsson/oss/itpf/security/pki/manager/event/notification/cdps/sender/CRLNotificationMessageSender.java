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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationMessage;

/**
 * CRLNotificationMessageSender class will send the CRLNotificationMessage to CDPS over a channel i.e ClusteredCRLNotificationChannel
 * 
 * @author xjagcho
 * 
 */
public class CRLNotificationMessageSender {

    @Inject
    @Modeled
    private EventSender<CRLNotificationMessage> crlNotificationMessageEventSender;

    @Inject
    private Logger logger;

    /**
     * This Method sends the CRL Notification message to the CDPS over ClusteredCRLNotificationChannel
     * 
     * @param crlNotificationMessage
     *            crlNotificationMessage contains list CACertificateInfo it contains caName and certificateserialNumber and CDPSOperationType.
     */
    @Profiled
    public void sendMessage(final CRLNotificationMessage crlNotificationMessage) {
        logger.debug("sendMessage method in CRLNotificationMessageSender class");

        crlNotificationMessageEventSender.send(crlNotificationMessage);

        logger.debug("End of sendMessage method in CRLNotificationMessageSender class");
    }
}