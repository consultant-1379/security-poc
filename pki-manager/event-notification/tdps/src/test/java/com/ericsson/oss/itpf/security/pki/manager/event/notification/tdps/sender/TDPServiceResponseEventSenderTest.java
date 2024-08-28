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
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender.TDPServiceResponseEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class TDPServiceResponseEventSenderTest {

    @InjectMocks
    TDPServiceResponseEventSender tdpserviceResponseEventSender;

    @Mock
    TDPServiceResponse tdpServiceResponse;

    @Mock
    EventSender<TDPServiceResponse> trustDistributionServiceResponseEventSender;

    @Test
    public void testSend() {

        tdpserviceResponseEventSender.send(tdpServiceResponse);

        Mockito.verify(trustDistributionServiceResponseEventSender).send(tdpServiceResponse);

    }

}
