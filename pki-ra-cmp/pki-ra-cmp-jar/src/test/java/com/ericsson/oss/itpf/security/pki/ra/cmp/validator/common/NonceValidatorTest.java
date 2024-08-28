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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common;

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
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.NonceValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.TransactionIdHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(MockitoJUnitRunner.class)
public class NonceValidatorTest {
    @InjectMocks
    NonceValidator nonceValidator;

    @Mock
    TransactionIdHandler transactionIDHandler;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    CMPMessageEntity entity;

    @Mock
    Logger logger;

    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKICertConfWithNullSenderNonce;
    private static RequestMessage pKIPollRequestWithNullSenderNonce;
    private static String transactionId;
    private static String senderName;
    private static String senderNonce = null;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage responseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.IP_WITH_WAIT_RESPONSE).generate(pkiRequestMessage, responseParameters);
        final PKIMessage pkiPollRequestMessageWithSenderNonce = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(requestParameters, responseMessage);

        final Parameters responseParameters1 = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters1);

        requestParameters.setNullSenderNonce(true);
        final PKIMessage pkiPollRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(requestParameters, responseMessage);
        final PKIMessage pkiCertConfRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        pKIRequestMessage = new RequestMessage(pkiPollRequestMessageWithSenderNonce.getEncoded());
        pKICertConfWithNullSenderNonce = new RequestMessage(pkiCertConfRequestMessage.getEncoded());
        pKIPollRequestWithNullSenderNonce = new RequestMessage(pkiPollRequestMessage.getEncoded());
        senderName = pKIRequestMessage.getSenderName();
        senderNonce = pKIRequestMessage.getRecepientNonce();
    }

    @Test
    public void testValidate() {
        final CMPMessageEntity cMPMessageEntity = setCMPMessageEntity();
        Mockito.when(transactionIDHandler.handle(pKIRequestMessage, false)).thenReturn(transactionId);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName)).thenReturn(cMPMessageEntity);
        nonceValidator.validate(pKIRequestMessage);
        Mockito.verify(transactionIDHandler).handle(pKIRequestMessage, false);
    }

    @Test(expected = NonceValidationException.class)
    public void testDiffValueForReceipientAndSenderNonce() {

        final CMPMessageEntity cMPMessageEntity = setCMPMessageEntity();
        cMPMessageEntity.setSenderNonce(pKIRequestMessage.getSenderNonce());
        Mockito.when(transactionIDHandler.handle(pKIRequestMessage, false)).thenReturn(transactionId);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName)).thenReturn(cMPMessageEntity);
        nonceValidator.validate(pKIRequestMessage);
        Mockito.verify(transactionIDHandler).handle(pKIRequestMessage, false);
    }

    @Test(expected = NonceValidationException.class)
    public void testforPollRequestNullSenderNonce() {
        final CMPMessageEntity cMPMessageEntity = setCMPMessageEntity();
        final String transactionId = pKIPollRequestWithNullSenderNonce.getBase64TransactionID();
        final String senderName = pKIPollRequestWithNullSenderNonce.getSenderName();
        Mockito.when(transactionIDHandler.handle(pKIPollRequestWithNullSenderNonce, false)).thenReturn(transactionId);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName)).thenReturn(cMPMessageEntity);

        nonceValidator.validate(pKIPollRequestWithNullSenderNonce);

        Mockito.verify(persistenceHandler).updateEntity(cMPMessageEntity);

    }

    @Test(expected = NonceValidationException.class)
    public void testNonceValidationException() {
        final CMPMessageEntity cMPMessageEntity = setCMPMessageEntity();
        cMPMessageEntity.setSenderNonce(null);
        Mockito.when(transactionIDHandler.handle(pKIRequestMessage, false)).thenReturn(transactionId);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName)).thenReturn(cMPMessageEntity);
        nonceValidator.validate(pKIRequestMessage);
        Mockito.verify(transactionIDHandler).handle(pKIRequestMessage, false);
    }

    private CMPMessageEntity setCMPMessageEntity() {
        final CMPMessageEntity cMPMessageEntity = new CMPMessageEntity();
        cMPMessageEntity.setStatus(MessageStatus.WAIT_FOR_ACK);
        cMPMessageEntity.setSenderNonce(senderNonce);
        return cMPMessageEntity;
    }

    @Test(expected = NonceValidationException.class)
    public void testforCertConfNullSenderNonce() {
        final CMPMessageEntity cMPMessageEntity = setCMPMessageEntity();
        final String transactionId = pKICertConfWithNullSenderNonce.getBase64TransactionID();
        final String senderName = pKICertConfWithNullSenderNonce.getSenderName();
        Mockito.when(transactionIDHandler.handle(pKICertConfWithNullSenderNonce, false)).thenReturn(transactionId);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName)).thenReturn(cMPMessageEntity);

        nonceValidator.validate(pKICertConfWithNullSenderNonce);

        Mockito.verify(persistenceHandler).updateEntity(cMPMessageEntity);

    }
}
