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
package com.ericsson.oss.itpf.security.pki.cdps.notification;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;

/**
 * CRLAcknowledgementSender class will sends the CRLAcknowledgement to PKI Manager over ClusteredCRLAcknowledgementChannel
 *
 * @author xjagcho
 *
 */
public class CRLAcknowledgementSender {

    @Inject
    @Modeled
    private EventSender<CRLResponseAckMessage> crlResponseAckMessageEventSender;

    @Inject
    private Logger logger;

    /**
     * This Method sends the Acknowledgement to PKI Manager over ClusteredCRLAcknowledgementChannel
     * 
     * @param CRLResponseAckMessage
     *            holds list of CACertificateInfo it contains caName,certificateSerialNumber and CDPSResponseType,CDPSOperationType
     * 
     */
    @Profiled
    public void sendMessage(final CRLResponseAckMessage crlResponseAckMessage) {
        logger.debug("sendMessage method in CRLAcknowledgementSender class");

        crlResponseAckMessageEventSender.send(crlResponseAckMessage);

        logger.debug("End of sendMessage method in CRLAcknowledgementSender class");
    }
}