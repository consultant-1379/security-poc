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

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

@RunWith(MockitoJUnitRunner.class)
public class TransactionIdGeneratorTest {

    @InjectMocks
    TransactionIdGenerator transactionIdGenerator;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    Logger logger;

    private static RequestMessage pKIRequestMessage;
    private static String transactionID = null;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
       	final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionID = pKIRequestMessage.getBase64TransactionID();

    }

    @Test
    public void testUniqueTransactionId() {
        final String senderName = pKIRequestMessage.getSenderName().toString();
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(null);

        final String returnedTransactionId = transactionIdGenerator.generateUniqueTransactionID(pKIRequestMessage);

        Mockito.verify(logger).info("Newly generated TransactionID is: {} ", returnedTransactionId, "checking again inDB for this newly created TransactionID");

    }

}
