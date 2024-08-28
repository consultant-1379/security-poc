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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender.TDPSCertificateEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSCertificateEventSenderTest {

    @InjectMocks
    TDPSCertificateEventSender tdpsCertificateEventSender;

    @Mock
    TDPSCertificateEvent tdpsCertificateEvent;

    @Mock
    EventSender<TDPSCertificateEvent> tDPSCertificateEventSender;

    @Test
    public void testSend() {
        tdpsCertificateEventSender.send(tdpsCertificateEvent);

        Mockito.verify(tDPSCertificateEventSender).send(tdpsCertificateEvent);

    }

}
