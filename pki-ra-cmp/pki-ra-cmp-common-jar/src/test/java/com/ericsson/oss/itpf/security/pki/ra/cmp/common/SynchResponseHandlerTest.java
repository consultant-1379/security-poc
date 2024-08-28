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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.service.CMPServiceCluster;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(MockitoJUnitRunner.class)
public class SynchResponseHandlerTest {

    @InjectMocks
    SynchResponseHandler handler;

    @Mock
    CMPTransactionResponseMap cMPTransactionResponseMap;

    @Mock
    CMPServiceCluster cmpServiceCluster;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    RestSynchResponse asynchResponse;

    @Mock
    Logger logger;

    @Test
    public void testHandleResponseAndSendNotification() {
        final String transactionID = "Testtransactionid";
        final byte[] signedResponseMessage = null;
        Mockito.when(cMPTransactionResponseMap.isTransactionIdExists(transactionID)).thenReturn(true);
        Mockito.when(cMPTransactionResponseMap.getRestSynchResponse(transactionID)).thenReturn(asynchResponse);
        handler.handleResponseAndSendNotification(transactionID, signedResponseMessage);
    }

    @Test
    public void testHandleResponseAndSendNotificationwithoutTransactionid() {
        final String transactionID = "Testtransactionid";
        final byte[] signedResponseMessage = null;
        Mockito.when(cMPTransactionResponseMap.getRestSynchResponse(transactionID)).thenReturn(asynchResponse);
        handler.handleResponseAndSendNotification(transactionID, signedResponseMessage);
    }

    @Test
    public void testHandleResponse() {
        final String transactionID = "Testtransactionid";
        CMPMessageEntity cmpMessageEntity = new CMPMessageEntity();
        cmpMessageEntity.setResponseMessage(null);
        Mockito.when(cMPTransactionResponseMap.isTransactionIdExists(transactionID)).thenReturn(true);
        Mockito.when(cMPTransactionResponseMap.getRestSynchResponse(transactionID)).thenReturn(asynchResponse);
        Mockito.when(persistenceHandler.fetchEntityByTransactionID(transactionID)).thenReturn(cmpMessageEntity);
        handler.handleResponse(transactionID);
    }

}
