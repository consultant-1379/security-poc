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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.event.PublishTDPSCertificateEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.event.UnPublishTDPSCertficateEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler.TDPSCertificateEventHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSCertificateEventHandlerTest {

    @InjectMocks
    TDPSCertificateEventHandler tdpsCertificateEventHandler;

    @Mock
    PublishTDPSCertificateEvent publishTDPSCertificateEvent;

    @Mock
    UnPublishTDPSCertficateEvent unPublishTDPSCertficateEvent;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testHandleForPublish() {
        TDPSCertificateEvent tDPSCertificateEvent = new TDPSCertificateEvent();
        TDPSOperationType tpdsOperationType = TDPSOperationType.PUBLISH;
        tDPSCertificateEvent.setTdpsOperationType(tpdsOperationType);

        tdpsCertificateEventHandler.handle(tDPSCertificateEvent);
        Mockito.verify(publishTDPSCertificateEvent).execute(tDPSCertificateEvent);
    }

    @Test
    public void testHandleForUnPublish() {
        TDPSCertificateEvent tDPSCertificateEvent = new TDPSCertificateEvent();
        TDPSOperationType tpdsOperationType = TDPSOperationType.UNPUBLISH;
        tDPSCertificateEvent.setTdpsOperationType(tpdsOperationType);

        tdpsCertificateEventHandler.handle(tDPSCertificateEvent);
        Mockito.verify(unPublishTDPSCertficateEvent).execute(tDPSCertificateEvent);
    }

    @Test
    public void testHandleForDefault() {
        TDPSCertificateEvent tDPSCertificateEvent = new TDPSCertificateEvent();
        TDPSOperationType tpdsOperationType = TDPSOperationType.UNKNOWN;
        tDPSCertificateEvent.setTdpsOperationType(tpdsOperationType);

        tdpsCertificateEventHandler.handle(tDPSCertificateEvent);
        Mockito.verify(logger).warn("Unknown TDPS Operation : {}", tDPSCertificateEvent.getTdpsOperationType().toString());
    }

}
