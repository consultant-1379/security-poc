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
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;

/**
 * CRLResponseMessageSender class will send the CRL information to PKI Manager over a channel i.e ClusteredCRLResponseChannel
 * 
 * @author xjagcho
 * 
 */
public class CRLResponseMessageSender {

    @Inject
    @Modeled
    private EventSender<CRLResponseMessage> crlResponseMessageEventSender;

    @Inject
    private Logger logger;

    /**
     * This Method sends the CRL Response Message to the CDPS over a ClusteredCRLResponseChannel to publish
     * 
     * @param crlsMessage
     *            crlsMessage contains list of CRLInfo it holds CACertificateInfo and encoded CRL
     */
    @Profiled
    public void sendMessage(final CRLResponseMessage crlMessage) {
        logger.debug("sendMessage method in CrlsMessageSender class");

        crlResponseMessageEventSender.send(crlMessage);

        logger.debug("End of sendMessage method in CrlsMessageSender class");
    }
}