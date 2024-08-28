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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.listener;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pkira.scep.event.ScepRequestMessage;

/**
 * ScepRequestMessageListener will listen the ScepRequestMessage from the ScepRequestChannel . Once the event is received the event will be sent to the ScepRequestProcessor.
 * 
 * @author xananer
 */

@ApplicationScoped
public class ScepRequestMessageListener {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * receiveScepRequestMessage will receive the ScepRequestMessage over the ScepRequestChannel and sends it to the scepRequestProcessor where the fetched message will be processed to extract and
     * validate CSR for generating certificate.
     * 
     * 
     * @param scepRequestMessage
     *            is the message which received over the ScepRequestChannel and contains the CSR and Transaction Id.
     * @throws IOException
     *             is thrown when the listener fails to fetch the data from the channel or if the connection is lost with the ScepRequestChannel.
     */
    // Listener for deprecated event ScepRequestMessage
    public void receiveScepRequestMessage(@Observes @Modeled final ScepRequestMessage scepRequestMessage) throws IOException {

        systemRecorder.recordEvent("PKI_MANAGER_SCEP.REQUEST_LISTENER", EventLevel.COARSE, "SCEPService", "ScepRequestMessageListener",
                "Received the deprecated ScepRequestMessage over the ScepRequestChannel");
        logger.info("Received the deprecated ScepRequestMessage over the ScepRequestChannel ");

    }
}
