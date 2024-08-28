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

import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLResponseMessageListener;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.PublishCRLEvent;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;

/**
 * This class used to test CRLResponseMessageListener functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLResponseMessageListenerTest {

    @InjectMocks
    CRLResponseMessageListener crlResponseMessageListener;

    @Mock
    private Logger logger;

    @Mock
    private PublishCRLEvent publishCRLEvent;

    private CRLResponseMessage crlResponseMessage;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        crlResponseMessage = new CRLResponseMessage();

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.CRLResponseMessageListener#receiveCRLMessage(com.ericsson.oss.itpf.security.pki.ra.cdps.event.CRLResponseMessage)} .
     */
    @Test
    public void testReceiveCRLMessage() {

        crlResponseMessageListener.receiveCRLResponseMessage(crlResponseMessage);

        Mockito.verify(publishCRLEvent, times(1)).execute(crlResponseMessage.getCrlInfoList());
    }

}
