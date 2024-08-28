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

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSResponse;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSEntityDataMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSResponseMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.EventNotificationPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder.TDPSAcknowledgementEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender.TDPSAcknowledgementEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class TDPServiceResponseHandlerTest {

    @InjectMocks
    TDPServiceResponseHandler tdpsServiceResponseHandler;

    @Mock
    TDPSEntityDataMapper tDPSEntityMapper;

    @Mock
    TDPSResponseMapper tDPSResponseMapper;

    @Mock
    TDPSAcknowledgementEventSender tdpsAcknowledgementEventSender;

    @Mock
    EventNotificationPersistenceHandler eventNotificationPersistenceHandler;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testHandle() {
        TDPServiceResponse tdpsServiceResponse = new TDPServiceResponse();
        tdpsServiceResponseHandler.handle(tdpsServiceResponse);
        Mockito.verify(tdpsAcknowledgementEventSender).send(Matchers.<TDPSAcknowledgementEvent> anyObject());
    }

    @Test
    public void testHandleException() {
        TDPServiceResponse tdpsServiceResponse = new TDPServiceResponse();
        Mockito.when((new TDPSAcknowledgementEventBuilder()).tDPSResponseType(tDPSResponseMapper.toModel(TDPSResponse.SUCCESS))).thenThrow(new PersistenceException());

        tdpsServiceResponseHandler.handle(tdpsServiceResponse);
        Mockito.verify(tdpsAcknowledgementEventSender).send(Matchers.<TDPSAcknowledgementEvent> anyObject());
    }

}
