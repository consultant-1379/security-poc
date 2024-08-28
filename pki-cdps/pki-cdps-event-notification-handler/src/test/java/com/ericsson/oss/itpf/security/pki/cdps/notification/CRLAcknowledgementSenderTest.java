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

import static org.mockito.Mockito.times;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test CRLAcknowledgementSender functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLAcknowledgementSenderTest extends SetUpData {

    @InjectMocks
    CRLAcknowledgementSender cRLAcknowledgementSender;

    @Mock
    private EventSender<CRLResponseAckMessage> crlResponseAckMessageEventSender;

    @Mock
    private Logger logger;

    private CRLResponseAckMessage crlResponseAckMsgPublish;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        crlResponseAckMsgPublish = new CRLResponseAckMessage();
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender#sendMessage(com.ericsson.oss.itpf.security.pki.ra.cdps.event.CRLResponseAckMessage)} Passing
     * CDPSOperationType.PUBLISH as parameter
     */
    @Test
    public void testSendMessagePublish() {

        cRLAcknowledgementSender.sendMessage(crlResponseAckMsgPublish);

        Mockito.verify(crlResponseAckMessageEventSender, times(1)).send(crlResponseAckMsgPublish);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender#sendMessage(com.ericsson.oss.itpf.security.pki.ra.cdps.event.CRLResponseAckMessage)} Passing
     * CDPSOperationType.UNPUBLISH as parameter
     */
    @Test
    public void testSendMessageUnPublish() {

        cRLAcknowledgementSender.sendMessage(crlResponseAckMsgPublish);

        Mockito.verify(crlResponseAckMessageEventSender, times(1)).send(crlResponseAckMsgPublish);

    }

}