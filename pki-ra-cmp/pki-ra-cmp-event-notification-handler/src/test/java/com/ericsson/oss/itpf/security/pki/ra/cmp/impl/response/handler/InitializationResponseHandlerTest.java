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

package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.jboss.resteasy.spi.AsynchronousResponse;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.CMPTransactionResponseMap;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.SynchResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.MessageSignerService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(MockitoJUnitRunner.class)
public class InitializationResponseHandlerTest {

    @InjectMocks
    InitializationResponseHandler initializationResponseHandler;

    @Mock
    CMPLocalService cmpLocalService;

    @Mock
    CMPResponse cMPResponse;

    @Mock
    CMPTransactionResponseMap cMPTransactionResponseMap;

    @Mock
    MessageSignerService messageSignerService;

    @Mock
    AsynchronousResponse asyncResponse;

    @Mock
    RestSynchResponse asynchResponse;

    @Mock
    SynchResponseHandler handler;

    @Mock
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    CMPMessageEntity cMPMessageEntity;

    @Mock
    Logger logger;

    private static RequestMessage pKIRequestMessage;
    private static ResponseMessage pKIResponseMessage;
    private static String transactionId;

    private static String ISSUERNAME = "TestCA";

    @BeforeClass
    public static void initializeTestData() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage expectedPKIRequestMessage =
                RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage expectedPKIResponseMessage =
                ResponseGeneratorFactory.getResponseGenerator(
                        com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType.INITIALIZATION_RESPONSE).generate(
                                expectedPKIRequestMessage, responseParameters);

        pKIRequestMessage = new RequestMessage(expectedPKIRequestMessage.getEncoded());
        pKIResponseMessage = new IPResponseMessage(expectedPKIResponseMessage.getEncoded());
        transactionId = pKIRequestMessage.getBase64TransactionID();
    }

    @Test
    public void testHandle() throws IOException {

        setUpTestData();

        initializationResponseHandler.handle(cMPResponse);
        Mockito.verify(cmpLocalService).updateCMPTransactionStatus(transactionId, pKIRequestMessage.getSenderName(),
                pKIResponseMessage.getPKIResponseMessage().getEncoded(),
                MessageStatus.WAIT_FOR_ACK, null);
    }

    private void setUpTestData() throws IOException {

        final byte[] ipResponseFromManager = pKIResponseMessage.toByteArray();
        Mockito.when(cMPResponse.getTransactionID()).thenReturn(transactionId);
        Mockito.when(cMPResponse.getCmpResponse()).thenReturn(ipResponseFromManager);
        Mockito.when(cMPResponse.getEntityName()).thenReturn(pKIRequestMessage.getSenderName());
    }

    @Test
    public void testHandleSyncResponse() throws ResponseSignerException, IOException {
        setUpTestData();
        cMPResponse.setSyncResponse(true);
        final String sender = "CN=sender";
        final String senderName = "CN=entity";
        final String entityName = "CN=entity";
        final String transactionID = transactionId;
        final byte[] signedResponseMessage = pKIResponseMessage.toByteArray();
        final byte[] responseFromManager = pKIResponseMessage.toByteArray();
        Mockito.when(cMPResponse.getSyncResponse()).thenReturn(true);
        Mockito.when(messageSignerService.getSenderFromSignerCert(ISSUERNAME)).thenReturn(sender);
        Mockito.when(cMPResponse.getEntityName()).thenReturn(entityName);
        Mockito.when(cMPResponse.getIssuerName()).thenReturn(ISSUERNAME);
        Mockito.when(cMPResponse.getProtectionAlgorithm()).thenReturn(pKIRequestMessage.getProtectAlgorithm().getEncoded());
        Mockito.when(cMPResponse.getCmpResponse()).thenReturn(responseFromManager);
        Mockito.when(messageSignerService.signMessage(Matchers.anyString(), Matchers.<IPResponseMessage>anyObject()))
                .thenReturn(signedResponseMessage);
        Mockito.when(cMPTransactionResponseMap.getRestSynchResponse(transactionID)).thenReturn(asynchResponse);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(cMPMessageEntity);
        initializationResponseHandler.handle(cMPResponse);
        Mockito.verify(messageSignerService).getSenderFromSignerCert(ISSUERNAME);
        Mockito.verify(messageSignerService).signMessage(Matchers.anyString(), Matchers.<IPResponseMessage>anyObject());
    }
}
