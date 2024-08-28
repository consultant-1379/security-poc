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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.listener;

import org.junit.Test;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CMPRequest;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.CMPServiceRequest;

@RunWith(MockitoJUnitRunner.class)
public class CMPServiceRequestListenerTest {

    @InjectMocks
    CMPServiceRequestListener cMPServiceRequestListener;

    @Mock
    CMPServiceRequest cMPServiceRequest;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testListenToRequest() {
        cMPServiceRequestListener.listenToRequest(cMPServiceRequest);
        Mockito.verify(logger).error("Received CMP Request is not signed,Invalid CMPService Request Sent from PKI-RA");
    }
}
