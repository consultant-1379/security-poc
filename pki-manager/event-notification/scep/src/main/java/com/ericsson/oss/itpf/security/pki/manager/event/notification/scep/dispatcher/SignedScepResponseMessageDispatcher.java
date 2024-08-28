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

package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.dispatcher;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * ScepResponseMessageDispatcher will send SignedScepResponseMessage which contains signed xml as byte array with attributes Transaction Id, Status, FailureInfo and Certificate over the ScepResponseChannel.
 * 
 * @author xnagsow
 *
 */

public class SignedScepResponseMessageDispatcher {

    @Inject
    @Modeled
    private EventSender<SignedScepResponseMessage> scepResponseSender;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * sendResponseMessage will send the SignedScepResponseMessage over the ScepResponseChannel. This ScepResponseMessage will contain signed xml as byte array with attributes Transaction Id, Status, FailureInfo and Certificate over the ScepResponseChannel.
     * 
     * @param signedScepResponseMessage
     *           is the signed Scep response Message for the given PKCSReq message which will contain digitally signed xml which in turn contains the Transaction Id and Status as success if the Certificate generation is successful. The
     *           responseMessage will contain the failureInfo message if the Certificate generation is failed,in that case the Certificate attribute will be null.
     */
    public void sendResponseMessage(final SignedScepResponseMessage signedScepResponseMessage) {
        scepResponseSender.send(signedScepResponseMessage);
        systemRecorder.recordEvent("PKI_MANAGER_SCEP.RESPONSE_CHANNEL", EventLevel.COARSE, "ScepResponseMessageDispatcher", "SCEP Service", "Signed Scep response message sent over Scep response channel");
    }
}
