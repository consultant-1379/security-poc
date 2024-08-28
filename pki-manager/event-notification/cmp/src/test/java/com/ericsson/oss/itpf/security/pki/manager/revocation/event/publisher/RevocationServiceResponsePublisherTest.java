/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.publisher;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class RevocationServiceResponsePublisherTest {

    @InjectMocks
    RevocationServiceResponsePublisher revocationServiceResponsePublisher;

    @Mock
    SignedRevocationServiceResponse revocationServiceResponseEvent;

    @Mock
    EventSender<SignedRevocationServiceResponse> revocationServiceResponseSender;

    @Mock
    Logger logger;

    @Test
    public void testPublish() {

        revocationServiceResponsePublisher.publish(revocationServiceResponseEvent);
        Mockito.verify(revocationServiceResponseSender).send(revocationServiceResponseEvent);

    }
}
