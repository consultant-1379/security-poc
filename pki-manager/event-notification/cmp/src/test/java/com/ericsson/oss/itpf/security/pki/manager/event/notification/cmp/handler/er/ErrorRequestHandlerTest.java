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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.FailureResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.SignedResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher.CMPServiceResponsePublisher;

@RunWith(MockitoJUnitRunner.class)
public class ErrorRequestHandlerTest {

    @InjectMocks
    ErrorRequestHandler errorRequestHandler;

    @Mock
    ErrorResponseBuilder failureResponseBuilder;

    @Mock
    CMPServiceResponsePublisher cMPServiceResponseDispatcher;

    @Mock
    SignedResponseBuilder requestHandlerUtility;

    @Mock
    Logger logger;

    private static final String ERROR_MESSAGE = "Error Message";

    private static RequestMessage pKIRequestMessage;
    private static String transactionId = null;
    private static CMPRequest cMPRequestXMLData = null;
    private static FailureResponseMessage failureResponseMessage = null;
    private static CMPResponse cMPResponseXMLData;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionId = pKIRequestMessage.getBase64TransactionID();
        setCMPRequestXMLData();
    }

    @Test
    public void testHandle() throws Exception {

        byte[] signedXMLData = pKIRequestMessage.toByteArray();
        failureResponseMessage = new FailureResponseMessage(pKIRequestMessage, ERROR_MESSAGE);
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);
        Mockito.when(requestHandlerUtility.buildSignedCMPResponse((CMPResponse)Matchers.anyObject())).thenReturn(signedXMLData);
        errorRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(logger).warn("RequestMessage from RA to Manager is neither IR nor KUR, hence an error message will be sent back to RA for the transactionID : {}", transactionId);
    }

    
    @Test
    public void testHandleSignedXMLDataNotNull() throws Exception {

        byte[] signedXMLData = pKIRequestMessage.toByteArray();
        failureResponseMessage = new FailureResponseMessage(pKIRequestMessage, ERROR_MESSAGE);
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);
        Mockito.when(requestHandlerUtility.buildSignedCMPResponse((CMPResponse)Matchers.anyObject())).thenReturn(signedXMLData);
        errorRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(logger).warn("RequestMessage from RA to Manager is neither IR nor KUR, hence an error message will be sent back to RA for the transactionID : {}", transactionId);
    }
    
    @Test
    public void testHandle_IOException() throws IOException {

        byte[] signedXMLData = pKIRequestMessage.toByteArray();
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenThrow(
                new IOException());
        Mockito.when(requestHandlerUtility.buildSignedCMPResponse(cMPResponseXMLData)).thenReturn(signedXMLData);
        errorRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(logger).warn("Unable to parse bytes sent from Queue for CMPService for TransactionId : {} ", cMPRequestXMLData.getTransactionId());
    }

    private static void setCMPRequestXMLData() throws Exception {
        byte[] cMPRequest = pKIRequestMessage.toByteArray();

        cMPRequestXMLData = new CMPRequest();
        cMPRequestXMLData.setCmpRequest(cMPRequest);
        cMPRequestXMLData.setTransactionId(transactionId);
        cMPRequestXMLData.setCmpRequest(cMPRequest);

    }
}
