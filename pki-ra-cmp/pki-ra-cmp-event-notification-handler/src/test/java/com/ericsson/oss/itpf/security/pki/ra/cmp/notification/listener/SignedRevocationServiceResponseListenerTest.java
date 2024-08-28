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

import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.handler.RevocationServiceResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener.SignedRevocationServiceResponseListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class SignedRevocationServiceResponseListenerTest {

    @InjectMocks
    SignedRevocationServiceResponseListener revocationServiceResponseListener;

    @Mock
    SignedRevocationServiceResponse revocationServiceResponse;

    @Mock
    RevocationServiceResponseHandler revocationServiceResponseHandler;

    @Test
    public void testListenForRevocationServiceResponse() {
        revocationServiceResponseListener.listenForRevocationServiceResponse(revocationServiceResponse);
        Mockito.verify(revocationServiceResponseHandler).handle(revocationServiceResponse);
    }
}
