package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class CMPServiceResponsePublisherTest {

    @InjectMocks
    CMPServiceResponsePublisher protocolServiceResponseDispatcher;

    @Mock
    Logger logger;

    @Mock
    EventSender<SignedCMPServiceResponse> cMPServiceResponseEventSender;

    private static SignedCMPServiceResponse cMPServiceResponse;

    @Test
    public void testDispatch() {

        protocolServiceResponseDispatcher.publish(cMPServiceResponse);
        Mockito.verify(cMPServiceResponseEventSender).send(cMPServiceResponse);

    }

}
