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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSAcknowledgementEventSenderTest {

    @InjectMocks
    TDPSAcknowledgementEventSender tdpsAcknowledgementEventSender;

    @Mock
    EventSender<TDPSAcknowledgementEvent> tDPSAcknowledgementEventSender;

    @Test
    public void testTDPSAcknowledgementEventSender() {
        TDPSAcknowledgementEvent tDPSAcknowledgementEvent = new TDPSAcknowledgementEvent();
        tdpsAcknowledgementEventSender.send(tDPSAcknowledgementEvent);
        Mockito.verify(tDPSAcknowledgementEventSender).send(tDPSAcknowledgementEvent);
    }

}
