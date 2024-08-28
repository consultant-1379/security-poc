package com.ericsson.oss.itpf.security.pki.ra.cmp.service.ejb;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;
import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.CMPTransactionResponseMap;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.instrumentation.CMPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusBuilder;

@RunWith(MockitoJUnitRunner.class)
public class CMPServiceBeanTest {

    @InjectMocks
    CMPServiceBean cMPServiceBean;

    @Mock
    RequestHandlerFactory requestHandlerFactory;

    @Mock
    ResponseBuilderFactory responseBuilderFactory;

    @Mock
    FailureMessageBuilder cMPFailureMessageBuilder;

    @Mock
    RequestHandler requestHandler;

    @Mock
    ResponseBuilder responseBuilder;

    @Mock
    RestSynchResponse aysnchResponse;

    @Mock
    CMPTransactionResponseMap cMPTransactionResponseMap;

    @Mock
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Mock
    Logger logger;

    @Mock
    CMPInstrumentationBean cmpInstrumentationBean;

    @Mock
    private SystemRecorder systemRecorder;

    private static RequestMessage pKIRequestMessage;
    private static String transactionId;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters parameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionId = pKIRequestMessage.getBase64TransactionID();
    }

    @Test
    public void testProvide() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        cMPServiceBean.provide(pKIRequestMessage);
        Mockito.verify(responseBuilderFactory).getResponseBuilder(pKIRequestMessage);
    }

    @Test
    public void testProvideForRestAsyn() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(pKIRequestMessage.getBase64TransactionID());
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenReturn(pKIRequestMessage.getProtectionBytes());
        cMPServiceBean.provide(pKIRequestMessage, aysnchResponse);
        Mockito.verify(logger).info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
    }

    @Test
    public void testValidationException() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new ValidationException());
        cMPServiceBean.provide(pKIRequestMessage);
        Mockito.verify(responseBuilderFactory).getResponseBuilder(pKIRequestMessage);
    }

    @Test
    public void testValidationExceptionForRestAsynch() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new ValidationException());
        cMPServiceBean.provide(pKIRequestMessage, aysnchResponse);
        Mockito.verify(logger).info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
    }

    @Test
    public void testResponseBuilderException() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new ResponseBuilderException());
        cMPServiceBean.provide(pKIRequestMessage);
        Mockito.verify(responseBuilderFactory).getResponseBuilder(pKIRequestMessage);
    }

    @Test
    public void testTransactionIdHandlerException() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenThrow(new TransactionIdHandlerException("Error"));
        cMPServiceBean.provide(pKIRequestMessage);
        Mockito.verify(requestHandler).handle(pKIRequestMessage);
    }

    @Test
    public void testTransactionIdHandlerExceptionForRestAsynch() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenThrow(new TransactionIdHandlerException("Error"));
        cMPServiceBean.provide(pKIRequestMessage, aysnchResponse);
        Mockito.verify(requestHandler).handle(pKIRequestMessage);
        Mockito.verify(logger).info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
    }

    @Test
    public void testProtocolException() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new ProtocolException());
        cMPServiceBean.provide(pKIRequestMessage);
        Mockito.verify(responseBuilder).build(pKIRequestMessage, transactionId);
    }

    @Test
    public void testProtocolExceptionForRestAsynch() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new ProtocolException());

        Mockito.doThrow(ProtocolException.class).when(cMPTransactionResponseMap).putRestSynchResponse(transactionId, aysnchResponse);

        cMPServiceBean.provide(pKIRequestMessage, aysnchResponse);
        Mockito.verify(logger).info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
    }

    @Test
    public void testValidationExceptionForRestAsynch1() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new ProtocolException());

        Mockito.doThrow(ValidationException.class).when(cMPTransactionResponseMap).putRestSynchResponse(transactionId, aysnchResponse);

        cMPServiceBean.provide(pKIRequestMessage, aysnchResponse);
        Mockito.verify(logger).info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
    }

    @Test
    public void testDigitalSigningFailedExceptionAysnchResponse() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.doThrow(DigitalSigningFailedException.class).when(cMPTransactionResponseMap).putRestSynchResponse(transactionId, aysnchResponse);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new DigitalSigningFailedException("DigitalSigningFailedException"));
        cMPServiceBean.provide(pKIRequestMessage, aysnchResponse);
        Mockito.verify(logger).info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
    }

    @Test
    public void testDigitalSigningFailedException() {
        Mockito.when(requestHandlerFactory.getRequestHandler(pKIRequestMessage)).thenReturn(requestHandler);
        Mockito.when(responseBuilderFactory.getResponseBuilder(pKIRequestMessage)).thenReturn(responseBuilder);
        Mockito.when(requestHandler.handle(pKIRequestMessage)).thenReturn(transactionId);
        Mockito.when(responseBuilder.build(pKIRequestMessage, transactionId)).thenThrow(new DigitalSigningFailedException("DigitalSigningFailedException"));
        cMPServiceBean.provide(pKIRequestMessage);
        Mockito.verify(responseBuilder).build(pKIRequestMessage, transactionId);
    }

}
