package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.processor.CMPServiceRequestProcessor;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceRequest;

@RunWith(MockitoJUnitRunner.class)
public class SignedCMPServiceRequestListenerTest {

    @InjectMocks
    SignedCMPServiceRequestListener protocolServiceRequestListener;

    @Mock
    RequestHandlerFactory protocolRequestHandlerFactory;

    @Mock
    SignedCMPServiceRequest cMPServiceRequest;

    @Mock
    CMPServiceRequestProcessor cmpServiceRequestProcessor;

    @Mock
    Logger logger;

    @Test
    public void testListenToRequest() {
        protocolServiceRequestListener.listenToRequest(cMPServiceRequest);
        Mockito.verify(cmpServiceRequestProcessor).processRequest(cMPServiceRequest);
    }

    @Test(expected = Exception.class)
    public void testListenToRequestException() {
        Mockito.doThrow(Exception.class).when(cmpServiceRequestProcessor).processRequest(cMPServiceRequest);
        protocolServiceRequestListener.listenToRequest(cMPServiceRequest);
        Mockito.verify(logger).error("Error in processing the request sent from CMP in SignedCMPServiceRequestListener null");
    }

}
