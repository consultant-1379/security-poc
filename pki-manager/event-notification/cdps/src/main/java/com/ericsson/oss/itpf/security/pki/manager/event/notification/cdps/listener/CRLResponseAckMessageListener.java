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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor.CRLResponseAckMessageProcessor;

/**
 * CRLAckResponseMessageListener will listen the CRL Response Acknowledgement Message from the ClusteredCRLResponseAckChannel. Once the event is received the event will be sent to the CRL
 * Acknowledgement Response Processor.
 * 
 * @author xjagcho
 */
@ApplicationScoped
public class CRLResponseAckMessageListener {

    @Inject
    private CRLResponseAckMessageProcessor crlResponseAckMessageProcessor;

    @Inject
    private Logger logger;

    /**
     * This method receives CRL Response Acknowledgement Message and process this message and update CRL Status in DB
     * 
     * @param crlResponseAckMessage
     *            crlResponseAckMessage holds the list of CACertificateInfo it contains caName,certificate SerialNumber and CDPSOperationType and CDPSResponseType
     */
    public void receiveCRLResponseAckMessage(@Observes @Modeled final CRLResponseAckMessage crlResponseAckMessage) {
        try {
            logger.debug("receiveCrlAcknowledgeMessage method in CRLResponseAckMessageListener class");

            crlResponseAckMessageProcessor.process(crlResponseAckMessage);

            logger.debug("End of receiveCrlAcknowledgeMessage method in CRLResponseAckMessageListener class");
        } catch (Exception exception) {
            logger.error("Exception found while updating CRL status in DB from CRL Response in CRLResponseAckMessageListener " + exception.getMessage());
            logger.debug("caught exception while processing the CRLResponseAckMessage in CRLResponseAckMessageListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }
}