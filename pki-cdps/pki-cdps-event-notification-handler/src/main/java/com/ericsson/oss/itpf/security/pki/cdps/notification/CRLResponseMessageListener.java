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

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.PublishCRLEvent;

/**
 * 
 * CRLResponseMessageListener will listen the CRLsMessage from the PKI Manager over ClusteredCRLResponseChannel. Once the event is received the event will be sent to the PublishCRLEvent. This will
 * Publish the CRL to CDPS and send the acknowledgement message to PKI Manager over a ClusteredCRLResponseAckChannel
 * 
 * @author xjagcho
 * 
 */
@ApplicationScoped
public class CRLResponseMessageListener {

    @Inject
    private Logger logger;

    @Inject
    private PublishCRLEvent publishCRLEvent;

    /**
     * Receives the CRLs from CRLMessage and Publish it to CDPS
     * 
     * @param crlResponseMessage
     *            crlResponseMessage contains list of CRL information as caName,certificateSerialNumber and CRL
     */
    public void receiveCRLResponseMessage(@Observes @Modeled final CRLResponseMessage crlResponseMessage) {
        try {
            handleMessage(crlResponseMessage);
        } catch (Exception exception) {
            logger.error("Exception caught while processing the crlResponseMessage in CRLResponseMessageListener " + exception.getMessage());
            logger.debug("Caught exception while Receiving the CRLs from CRLMessage and Publish it to CDPS in CRLResponseMessageListener {} ", exception.getMessage(), exception);
            throw exception;
        }
    }

    /**
     * This method handles the crlResponseMessage with list of CRL information as caName,certificateSerialNumber and CRL for to persist CRL information
     * 
     * @param crlResponseMessage
     *            crlResponseMessage contains list of CRL information as caName,certificateSerialNumber and CRL
     */
    private void handleMessage(final CRLResponseMessage crlResponseMessage) {

        logger.debug("handleMessage of CRLResponseMessageListener class in CDPS");

        publishCRLEvent.execute(crlResponseMessage.getCrlInfoList());

        logger.debug("End of method handleMessage of CRLResponseMessageListener class in CDPS");

    }
}