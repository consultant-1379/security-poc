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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(PowerMockRunner.class)
public class TransactionIdHandlerTest {

    @InjectMocks
    TransactionIdHandler transactionIdHandler;

    @Mock
    Logger logger;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    TransactionIdGenerator transactionIDGenerator;

    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKIReqWithoutTransactionId;
    private static String senderName;

    @BeforeClass
    public static void initializeTestData() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
    	final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        senderName = pKIRequestMessage.getSenderName();

        requestParameters.setSendTransactionID(false);
        final PKIMessage pkiRequestMessageWithoutTransactionID = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIReqWithoutTransactionId = new RequestMessage(pkiRequestMessageWithoutTransactionID.getEncoded());

    }

    @Test(expected = TransactionIdHandlerException.class)
    public void testTransactionIdNotPresentinDBForPolling() {

        final boolean tobeGenerated = false;
        final String transactionID = pKIRequestMessage.getBase64TransactionID();
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(null);

        transactionIdHandler.handle(pKIRequestMessage, tobeGenerated);

        Mockito.verify(persistenceHandler, times(1)).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);

    }

    @Test
    public void testValidateWithoutTransactionIdForIR() {

        final boolean tobeGenerated = true;
        final String transactionID = pKIReqWithoutTransactionId.getBase64TransactionID();
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(null);

        transactionIdHandler.handle(pKIReqWithoutTransactionId, tobeGenerated);

        Mockito.verify(persistenceHandler, never()).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);

    }

    @Test(expected = TransactionIdHandlerException.class)
    public void testValidateWithoutTransactionIdForPolling() {

        final boolean tobeGenerated = false;
        final String transactionID = pKIReqWithoutTransactionId.getBase64TransactionID();
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(null);

        transactionIdHandler.handle(pKIReqWithoutTransactionId, tobeGenerated);

        Mockito.verify(persistenceHandler, never()).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);

    }

    @Test(expected = TransactionIdHandlerException.class)
    public void testTransactionIdPresentInDB() {

        final boolean tobeGenerated = true;
        final String transactionID = pKIRequestMessage.getBase64TransactionID();
        final CMPMessageEntity cmpMessageEntity = new CMPMessageEntity();
        cmpMessageEntity.setTransactionID(transactionID);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(cmpMessageEntity);

        transactionIdHandler.handle(pKIRequestMessage, tobeGenerated);

        Mockito.verify(persistenceHandler, never()).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);

    }

}
