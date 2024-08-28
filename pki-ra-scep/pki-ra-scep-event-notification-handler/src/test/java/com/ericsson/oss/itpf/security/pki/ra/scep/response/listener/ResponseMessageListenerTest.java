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

import java.io.IOException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.response.processor.ResponseProcessor;
import com.ericsson.oss.itpf.security.pkira.scep.event.ScepResponseMessage;

/**
 * This class contains tests for ResponseMessageListener
 */
@RunWith(MockitoJUnitRunner.class)
public class ResponseMessageListenerTest {

    @InjectMocks
    private ResponseMessageListener responseMessageListener;
    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    ResponseProcessor responseProcessor;

    private ScepResponseMessage scepResponseMessage;

    @Before
    public void setUp() {
        scepResponseMessage = new ScepResponseMessage();
        scepResponseMessage.setTransactionId("12345");
    }

    /**
     * This method tests receiving ScepResponseMessage over ScepResponseChannel
     */
    @Test
    public void receiveScepMessageTest() {
        try {
            responseMessageListener.receiveResponseMessage(scepResponseMessage);
            Mockito.verify(logger).info("Depricated ScepResponseMessage with transactionId " + scepResponseMessage.getTransactionId() + " received over the ScepResponseChannel");
        } catch (IOException e) {
            Assert.fail(e.getMessage());
        }
    }
}
