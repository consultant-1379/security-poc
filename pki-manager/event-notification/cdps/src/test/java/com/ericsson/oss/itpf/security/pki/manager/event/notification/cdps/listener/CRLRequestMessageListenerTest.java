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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.listener.CRLRequestMessageListener;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor.CRLResponseMessageProcessor;

@RunWith(MockitoJUnitRunner.class)
public class CRLRequestMessageListenerTest {

    @InjectMocks
    CRLRequestMessageListener crlRequestMessageListener;

    @Mock
    private CRLResponseMessageProcessor crlResponseMessageProcessor;

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

    @Test
    public void receiveCRLRequestMessage() {
        crlRequestMessageListener.receiveCRLRequestMessage(crlRequestMessage);
    }

}
