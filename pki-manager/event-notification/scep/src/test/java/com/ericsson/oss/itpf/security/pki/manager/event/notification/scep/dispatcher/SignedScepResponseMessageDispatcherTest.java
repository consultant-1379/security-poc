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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.dispatcher;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

@RunWith(MockitoJUnitRunner.class)
public class SignedScepResponseMessageDispatcherTest {

    @InjectMocks
    SignedScepResponseMessageDispatcher scScepResponseMessageDispatcher;

    @Mock
    EventSender<SignedScepResponseMessage> scepResponseSender;

    @Mock
    private SystemRecorder systemRecorder;

    private SignedScepResponseMessage signedScepResponseMessage;

    @Before
    public void setup() {
        signedScepResponseMessage = new SignedScepResponseMessage();
    }

    @Test
    public void testProcessRequest() throws IOException {

        Mockito.doNothing().when(scepResponseSender).send(signedScepResponseMessage);
        scScepResponseMessageDispatcher.sendResponseMessage(signedScepResponseMessage);
        Mockito.verify(scepResponseSender).send(signedScepResponseMessage);

    }
}
