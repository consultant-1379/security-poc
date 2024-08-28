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
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLRequestMessageSender;

/**
 * This class used to test CRLRequestMessageSender functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLRequestMessageSenderTest {

    @InjectMocks
    CRLRequestMessageSender crlRequestMessageSender;

    @Mock
    private EventSender<CRLRequestMessage> crlRequestMessageEventSender;

    @Mock
    private Logger logger;

    private CRLRequestMessage crlRequestMessage;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        crlRequestMessage = new CRLRequestMessage();

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.CRLRequestMessageSender#sendMessage(com.ericsson.oss.itpf.security.pki.ra.cdps.event.CRLRequestMessage)} .
     */
    @Test
    public void testSendMessage() {

        crlRequestMessageSender.sendMessage(crlRequestMessage);

        Mockito.verify(crlRequestMessageEventSender, times(1)).send(crlRequestMessage);
    }

}
