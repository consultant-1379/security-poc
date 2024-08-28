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
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.revocation.event.handler.RevocationServiceRequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.RevocationServiceRequestEvent;

@RunWith(MockitoJUnitRunner.class)
public class RevocationServiceRequestListenerTest {

    @InjectMocks
    RevocationServiceRequestListener revocationServiceRequestListener;

    @Mock
    RevocationServiceRequestEvent revocationServiceRequest;

    @Mock
    RevocationServiceRequestHandler revocationRequestProcessor;

    @Mock
    Logger logger;

    @Test
    public void testListen() {
        revocationServiceRequestListener.listen(revocationServiceRequest);

    }
}
