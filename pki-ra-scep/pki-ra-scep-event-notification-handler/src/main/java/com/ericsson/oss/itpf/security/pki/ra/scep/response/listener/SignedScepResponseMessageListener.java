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
package com.ericsson.oss.itpf.security.pki.ra.scep.response.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.ra.scep.response.processor.ResponseProcessor;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * ResponseMessageListener will fetch the ScepResponseMessage event from the ScepResponseChannel. ScepResponseMessage contains digitally signed scep response message in the form of byte array.
 * 
 * @author xananer
 */
@ApplicationScoped
public class SignedScepResponseMessageListener {

    @Inject
    private Logger logger;

    @Inject
    private ResponseProcessor responseProcessor;

    /**
     * receiveResponseMessage is the listener method which receives a SignedScepResponseMessage over the ScepResponseChannel.
     * 
     * @param signedScepResponseMessage
     *            contains digitally signed scep response message in the form of byte array.
     */
    @Profiled
    public void receiveResponseMessage(@Observes @Modeled final SignedScepResponseMessage signedScepResponseMessage) {

        try {
            logger.info("SignedScepResponseMessage received over the ScepResponseChannel");
            responseProcessor.processResponse(signedScepResponseMessage);
        } catch (Exception exception) {
            logger.error("Exception found while processing scep response in SignedScepResponseMessageListener " + exception.getMessage());
            logger.debug("caught exception while processing the SignedScepResponseMessage in SignedScepResponseMessageListener {}  ", exception.getMessage(), exception);
            throw exception;
        }

    }
}
