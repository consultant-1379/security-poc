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
 *----------------------------------------------------------------------------
*/
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers.TDPSAcknowledgementRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.listener.TDPSAcknowledgementRequestListener;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSAcknowledgementRequestListenerTest {

    @InjectMocks
    TDPSAcknowledgementRequestListener tdpsAcknowledgementRequestListener;

    @Mock
    Logger logger;

    @Mock
    TDPSAcknowledgementEvent tdpsAcknowledgementEvent;

    @Mock
    TDPSAcknowledgementRequestHandler tDPSAcknowledgementRequestHandler;

    @Test
    public void testListenForTDPSAcknowledgementEvent() {

        tdpsAcknowledgementRequestListener.listenForTDPSAcknowledgementEvent(tdpsAcknowledgementEvent);

        Mockito.verify(tDPSAcknowledgementRequestHandler).handle(tdpsAcknowledgementEvent);

    }

}
