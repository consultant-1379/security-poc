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
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.handler.PKIManagerCMPResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener.SignedCMPServiceResponseListener;

@RunWith(MockitoJUnitRunner.class)
public class ProtocolServiceResponseEventListenerTest {

    @InjectMocks
    SignedCMPServiceResponseListener protocolServiceResponseEventListener;

    @Mock
    SignedCMPServiceResponse cMPServiceResponse;

    @Mock
    PKIManagerCMPResponseHandler pkiManagerCMPResponseHandler;

    @Mock
    Logger logger;

    @Test
    public void testListenToResponse() {

        protocolServiceResponseEventListener.listenToResponse(cMPServiceResponse);
        Mockito.verify(pkiManagerCMPResponseHandler).handle(cMPServiceResponse);

    }
}
