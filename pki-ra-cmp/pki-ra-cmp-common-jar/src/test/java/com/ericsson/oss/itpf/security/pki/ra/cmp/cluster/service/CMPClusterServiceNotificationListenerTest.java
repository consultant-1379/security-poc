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
package com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.service.CMPClusterServiceNotificationListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.SynchResponseHandler;

@RunWith(MockitoJUnitRunner.class)
public class CMPClusterServiceNotificationListenerTest {

    @Mock
    SynchResponseHandler synchResponseHandler;

    @Mock
    Logger logger;

    @InjectMocks
    CMPClusterServiceNotificationListener cmpClusterServiceNotificationListener;

    @Test
    public void testOnMessage() {
        final String transactionId = "testString";
        cmpClusterServiceNotificationListener.onMessage(transactionId);
    }
}
