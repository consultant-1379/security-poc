/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.revocation.event.handler.RevocationServiceRequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;

@RunWith(MockitoJUnitRunner.class)
public class SignedRevocationServiceRequestListenerTest {
    @InjectMocks
    SignedRevocationServiceRequestListener signedRevocationServiceRequestListener;

    @Mock
    SignedRevocationServiceRequest signedRevocationServiceRequest;

    @Mock
    Logger logger;

    @Mock
    private RevocationServiceRequestHandler revocationRequestProcessor;

    @Test
    public void testListen() {
        signedRevocationServiceRequestListener.listen(signedRevocationServiceRequest);
        Mockito.verify(logger).debug("receiveGetCrlRequestMessage of CRLRequestMessageListener class");

    }

    @Test(expected = Exception.class)
    public void testListenException() {
        Mockito.doThrow(Exception.class).when(revocationRequestProcessor).handle(signedRevocationServiceRequest);
        signedRevocationServiceRequestListener.listen(signedRevocationServiceRequest);
        Mockito.verify(logger).error("Exception occured while handling the revocation request from cmp in SignedRevocationServiceRequestListener null");
    }
}
