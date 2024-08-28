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
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener.RevocationServiceResponseListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.RevocationServiceResponseEvent;

@RunWith(MockitoJUnitRunner.class)
public class RevocationServiceResponseListenerTest {

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @InjectMocks
    RevocationServiceResponseListener revocationServiceResponseListener;

    @Mock
    RevocationServiceResponseEvent revocationServiceResponse;

    @Test
    public void testListenToResponse() {
        revocationServiceResponseListener.listenToResponse(revocationServiceResponse);
        Mockito.verify(logger).error("Received Revocation Response is not signed.So, the Response Message Sent by Manager is invalid.");

    }
}
