package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.UnsupportedRequestTypeException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;

@RunWith(MockitoJUnitRunner.class)
public class RequestHandlerFactoryImplTest {
    @InjectMocks
    RequestHandlerFactoryImpl cMPRequestHandlerFactoryImpl;

    @Mock
    private RequestHandler initializationRequestHandler;

    @Mock
    private RequestHandler certConfRequestHandler;

    @Mock
    private RequestHandler pollRequestHandler;

    @Mock
    private RequestHandler keyUpdateRequestHandler;

    @Mock
    Logger logger;

    private static RequestMessage pKIInitRequestMessage;
    private static RequestMessage pKIPollRequestMessage;
    private static RequestMessage pKIKURMessage;
    private static RequestMessage pKICertConfMessage;
    private static RequestMessage pKINotSupportedRequestMessage;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);

        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);
        final PKIMessage pkiPollRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(requestParameters, pkiResponseMessage);
        final PKIMessage pkiKurMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(requestParameters, null);
        final PKIMessage pkiCertConfMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        requestParameters.setValidRequestType(false);
        final PKIMessage pkiNotSupportedRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        pKIInitRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIPollRequestMessage = new RequestMessage(pkiPollRequestMessage.getEncoded());
        pKIKURMessage = new RequestMessage(pkiKurMessage.getEncoded());
        pKICertConfMessage = new RequestMessage(pkiCertConfMessage.getEncoded());
        pKINotSupportedRequestMessage = new RequestMessage(pkiNotSupportedRequestMessage.getEncoded());
    }

    @Test
    public void testGetRequestHandlerForIR() {
        initializationRequestHandler = cMPRequestHandlerFactoryImpl.getRequestHandler(pKIInitRequestMessage);
        assertThat(initializationRequestHandler, instanceOf(RequestHandler.class));
    }

    @Test
    public void testGetRequestHandlerPollRequest() {
        pollRequestHandler = cMPRequestHandlerFactoryImpl.getRequestHandler(pKIPollRequestMessage);
        assertThat(pollRequestHandler, instanceOf(RequestHandler.class));
    }

    @Test
    public void testGetRequestHandlerKUR() {
        keyUpdateRequestHandler = cMPRequestHandlerFactoryImpl.getRequestHandler(pKIKURMessage);
        assertThat(keyUpdateRequestHandler, instanceOf(RequestHandler.class));
    }

    @Test
    public void testGetRequestHandlerCertConf() throws Exception {
        certConfRequestHandler = cMPRequestHandlerFactoryImpl.getRequestHandler(pKICertConfMessage);
        assertThat(certConfRequestHandler, instanceOf(RequestHandler.class));
    }

    @Test(expected = UnsupportedRequestTypeException.class)
    public void testUnsupportedRequestException() {
        cMPRequestHandlerFactoryImpl.getRequestHandler(pKINotSupportedRequestMessage);
    }

}
