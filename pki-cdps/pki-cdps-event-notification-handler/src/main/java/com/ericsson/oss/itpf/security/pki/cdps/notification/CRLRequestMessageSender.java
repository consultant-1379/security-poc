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
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;

/**
 * CRLRequestMessageSender class will send the CRLRequestMessage to PKI Manager over ClusteredCRLClientChannel
 * 
 * @author xjagcho
 *
 */
public class CRLRequestMessageSender {

    @Inject
    @Modeled
    private EventSender<CRLRequestMessage> crlRequestMessageEventSender;

    @Inject
    private Logger logger;

    /**
     * This Method sends an event CRLRequestMessage to PKI Manager over ClusteredCRLClientChannel
     * 
     * @param crlRequestMessage
     *            crlRequestMessage holds list of CACertificate information and it contains CANAme,CertificateSerialNumber
     * 
     */
    @Profiled
    public void sendMessage(final CRLRequestMessage crlRequestMessage) {
        logger.debug("sendMessage method in CrlRequestMessageSender class");

        crlRequestMessageEventSender.send(crlRequestMessage);

        logger.debug("End of sendMessage method in CrlRequestMessageSender class");
    }
}