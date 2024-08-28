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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.listener;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.processor.ScepRequestProcessor;
import com.ericsson.oss.itpf.security.pkira.scep.event.ScepRequestMessage;

@RunWith(MockitoJUnitRunner.class)
public class ScepRequestMessageListenerTest {

    @InjectMocks
    ScepRequestMessageListener scepRequestMessageListener;

    @Mock
    private ScepRequestProcessor scepRequestProcessor;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Test
    public void testProcessRequest() throws IOException {
        ScepRequestMessage scepRequestMessage = new ScepRequestMessage();
        scepRequestMessageListener.receiveScepRequestMessage(scepRequestMessage);
        Mockito.verify(logger).info("Received the deprecated ScepRequestMessage over the ScepRequestChannel ");

    }

}
