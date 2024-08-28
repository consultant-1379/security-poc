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
package com.ericsson.oss.itpf.security.pki.ra.scep.event.sender;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.ra.scep.event.sender.SignedScepRequestMessageSender;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepRequestMessage;

/**
 * This class contains tests for RequestMessageSender
 */
@RunWith(MockitoJUnitRunner.class)
public class SignedScepRequestMessageSenderTest {

    @InjectMocks
    private SignedScepRequestMessageSender requestMessageSender;

    @Mock
    EventSender<SignedScepRequestMessage> signedScepRequestSender;
    @Mock
    Logger logger;

    private SignedScepRequestMessage signedScepRequestMessage;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @SuppressWarnings("unchecked")
    @Before
    public void setUp() {
        signedScepRequestSender = Mockito.mock(EventSender.class);
        signedScepRequestMessage = new SignedScepRequestMessage();
    }

    /**
     * This method tests sending scepRequestMessage over scepREquestChannel
     */
    @Test
    public void testSendMessageToscepRequestChannel() {
        Mockito.doNothing().when(signedScepRequestSender).send(signedScepRequestMessage);
        requestMessageSender.sendMessageToScepRequestChannel(signedScepRequestMessage);
        Mockito.verify(logger).info("SignedScepRequestMessage is placed in ScepRequestChannel");
    }

}
