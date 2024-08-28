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
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor.CRLResponseMessageProcessor;

/**
 * CRLRequestMessageListener will listen the CRL Request Message from the ClusteredCRLRequestChannel. Once the event is received the event will be sent to the CRL Message Processor.
 * 
 * @author xjagcho
 */
@ApplicationScoped
public class CRLRequestMessageListener {

    @Inject
    private CRLResponseMessageProcessor crlResponseMessageProcessor;

    @Inject
    private Logger logger;

    /**
     * This method process the CRL Request Message to get list of CRLs to be publish
     * 
     * @param crlRequestMessage
     *            crlRequestMessage contains list of CACertificateInfo it contains caName, serialNumber
     */
    public void receiveCRLRequestMessage(@Observes @Modeled final CRLRequestMessage crlRequestMessage) {
        try {
            logger.debug("receiveGetCrlRequestMessage of CRLRequestMessageListener class");

            crlResponseMessageProcessor.process(crlRequestMessage);

            logger.debug("End of method receiveGetCrlRequestMessage of CRLRequestMessageListener class");
        } catch (Exception exception) {
            logger.error("Exception occured while building the CRL Response in CRLRequestMessageListener " + exception.getMessage());
            logger.debug("caught exception while processing the CRLRequestMessage in CRLRequestMessageListener {}  ", exception.getMessage(), exception);
        }
    }
}