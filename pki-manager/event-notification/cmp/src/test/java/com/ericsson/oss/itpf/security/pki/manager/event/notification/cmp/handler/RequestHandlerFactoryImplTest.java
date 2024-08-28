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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er.ErrorRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir.InitializationRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.kur.KeyUpdateRequestHandler;

@RunWith(MockitoJUnitRunner.class)
public class RequestHandlerFactoryImplTest {

    @InjectMocks
    RequestHandlerFactoryImpl protocolRequestHandlerFactoryImpl;

    @Mock
    InitializationRequestHandler initializationRequestHandler;

    @Mock
    KeyUpdateRequestHandler keyUpdateRequestHandler;

    @Mock
    ErrorRequestHandler errorRequestHandler;

    @Mock
    Logger logger;

    @Mock
    CMPRequest cMPRequest;

    @Test
    public void testGetRequestHandler_ForErrorRequestTYPE_INIT_REQ() {
        Mockito.when(cMPRequest.getRequestType()).thenReturn(0);

        protocolRequestHandlerFactoryImpl.getRequestHandler((cMPRequest));

        assertThat(initializationRequestHandler, instanceOf(InitializationRequestHandler.class));

    }

    @Test
    public void testGetRequestHandler_TYPE_KEY_UPDATE_REQ() {
        Mockito.when(cMPRequest.getRequestType()).thenReturn(7);

        protocolRequestHandlerFactoryImpl.getRequestHandler((cMPRequest));

        assertThat(keyUpdateRequestHandler, instanceOf(KeyUpdateRequestHandler.class));

    }

    @Test
    public void testGetRequestHandler_ForErrorRequest() {
        Mockito.when(cMPRequest.getRequestType()).thenReturn(10);

        protocolRequestHandlerFactoryImpl.getRequestHandler(cMPRequest);

        assertThat(errorRequestHandler, instanceOf(ErrorRequestHandler.class));

    }

}
