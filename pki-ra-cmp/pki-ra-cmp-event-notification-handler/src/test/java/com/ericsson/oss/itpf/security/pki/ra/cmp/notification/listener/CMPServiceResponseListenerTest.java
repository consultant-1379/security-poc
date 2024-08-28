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
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.CMPServiceResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.listener.CMPServiceResponseListener;

@RunWith(MockitoJUnitRunner.class)
public class CMPServiceResponseListenerTest {

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @InjectMocks
    CMPServiceResponseListener cMPServiceResponseListener;

    @Mock
    CMPServiceResponse cMPServiceResponse;

    @Test
    public void testListenToResponse() {
        cMPServiceResponseListener.listenToResponse(cMPServiceResponse);
        Mockito.verify(logger).error("Received CMP Response is not Signed.So, the CMP Response Sent from PKI-Manager is Invalid");

    }
}
