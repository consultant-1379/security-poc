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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.dispatcher;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;

@RunWith(MockitoJUnitRunner.class)
public class RevocationServiceRequestDispatcherTest {

    @InjectMocks
    RevocationServiceRequestDispatcher revocationServiceRequestDispatcher;

    @Mock
    SignedRevocationServiceRequest revocationServiceRequest;

    @Mock
    EventSender<SignedRevocationServiceRequest> revocationServiceRequestSender;

    @Mock
    Logger logger;

    @Test
    public void testDispatch() {

        revocationServiceRequestDispatcher.dispatch(revocationServiceRequest);
        Mockito.verify(revocationServiceRequestSender).send(revocationServiceRequest);

    }
}
