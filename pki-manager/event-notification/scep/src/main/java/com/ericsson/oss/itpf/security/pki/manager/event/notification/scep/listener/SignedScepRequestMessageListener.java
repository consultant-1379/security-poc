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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.processor.ScepRequestProcessor;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepRequestMessage;

/**
 * SignedScepRequestMessageListener will listen the ScepRequestMessage from the ScepRequestChannel. Once the event is received the event will be sent to the ScepRequestProcessor.
 * 
 * @author xnagsow
 */

@ApplicationScoped
public class SignedScepRequestMessageListener {

    @Inject
    private ScepRequestProcessor scepRequestProcessor;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * receiveScepRequestMessage will receive the SignedScepRequestMessage over the ScepRequestChannel and sends it to the scepRequestProcessor where the fetched message will be processed to extract
     * and validate CSR for generating certificate.
     * 
     * @param signedScepRequestMessage
     *            is the message which received over the ScepRequestChannel and contains signed xml as byte array which in turn contains CSR and Transaction Id.
     */

    public void receiveScepRequestMessage(@Observes @Modeled final SignedScepRequestMessage signedScepRequestMessage) {
        try {
            logger.info("Entering method receiveScepRequestMessage of class ScepRequestMessageListener ");
            systemRecorder.recordEvent("PKI_MANAGER_SCEP.REQUEST_LISTENER", EventLevel.COARSE, "SCEPService", "ScepRequestMessageListener",
                    "Received the SignedScepRequestMessage over the ScepRequestChannel");
            scepRequestProcessor.processRequest(signedScepRequestMessage);
            logger.info("End of method receiveScepRequestMessage of class ScepRequestMessageListener ");
        } catch (Exception exception) {
            logger.error("Exception caught while processing the scep request in SignedScepRequestMessageListener " + exception.getMessage());
            logger.debug("caught exception while processing the SignedScepRequestMessage in SignedScepRequestMessageListener {}  ", exception.getMessage(), exception);
            throw exception;
        }

    }
}
