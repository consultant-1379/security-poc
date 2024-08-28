/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.event.sender;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepRequestMessage;

/**
 * RequestMessageSender will dispatch the SignedScepRequestMessage event into the ScepRequestChannel. This SignedScepRequestMessage contains digitally signed scep request message in the form of byte array.
 *
 * @author xananer
 */
public class SignedScepRequestMessageSender {

    @Inject
    @Modeled
    private EventSender<SignedScepRequestMessage> signedScepRequestSender;

    @Inject
    private Logger logger;

    /**
     * This Method sends a ScepRequestMessage into the ScepRequestChannel when a PKCSRequest is received from SCEP client.
     * 
     * @param signedScepRequestMessage
     *            contains digitally signed scep request message in the form of byte array.
     */
    @Profiled
    public void sendMessageToScepRequestChannel(final SignedScepRequestMessage signedScepRequestMessage) {
        logger.info("SignedScepRequestMessage is placed in ScepRequestChannel");
        signedScepRequestSender.send(signedScepRequestMessage);
    }
}
