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
package com.ericsson.oss.itpf.security.pki.ra.scep.response.listener;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pkira.scep.event.ScepResponseMessage;

/**
 * ResponseMessageListener will fetch the ScepResponseMessage event from the ScepResponseChannel. ScepResponseMessage contains the TransactionId, Status , Certificate and FailureInfo.
 * 
 * @author xananer
 */
@ApplicationScoped
public class ResponseMessageListener {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * receiveScepMessage is the listener method which receives a ScepResponseMessage over the ScepResponseChannel.
     * 
     * @param scepResponseMessage
     *            contains TransactionId, Status, Certificate and FailureInfo.
     * @throws IOException
     *             is thrown when the connection for the ScepMessageChannel is detached.
     */
    @Profiled
    public void receiveResponseMessage(@Observes @Modeled final ScepResponseMessage scepResponseMessage) throws IOException {
        logger.info("Depricated ScepResponseMessage with transactionId " + scepResponseMessage.getTransactionId() + " received over the ScepResponseChannel");
        systemRecorder.recordEvent("PKI_RA_SCEP.RESPONSE_MESSAGE_RECEIVED", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollement for End Entity",
                "Depricated Scep response message received over the Scep response channel for the Transaction Id :" + scepResponseMessage.getTransactionId());

    }
}
