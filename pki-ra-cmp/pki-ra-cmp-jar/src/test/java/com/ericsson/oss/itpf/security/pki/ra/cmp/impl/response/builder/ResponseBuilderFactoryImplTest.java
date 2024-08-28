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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder;

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

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;

@RunWith(MockitoJUnitRunner.class)
public class ResponseBuilderFactoryImplTest {
    @InjectMocks
    ResponseBuilderFactoryImpl responseBuilderFactoryImpl;

    @Mock
    ResponseBuilder ipWithWaitResponseBuilder;

    @Mock
    ResponseBuilder keyUpdateWithWaitResponseBuilder;

    @Mock
    ResponseBuilder pkiConfResponseBuilder;

    @Mock
    ResponseBuilder pollResponseBuilder;

    public static final String SENDER = "CN=Entity";
    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKIPollRequestMessage;
    private static RequestMessage pKIKURMessage;
    private static RequestMessage pKICertConfMessage;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);
        final PKIMessage pkiPollRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(requestParameters, pkiResponseMessage);
        final PKIMessage pkiKurMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(requestParameters, null);
        final PKIMessage pkiCertConfMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIPollRequestMessage = new RequestMessage(pkiPollRequestMessage.getEncoded());
        pKIKURMessage = new RequestMessage(pkiKurMessage.getEncoded());
        pKICertConfMessage = new RequestMessage(pkiCertConfMessage.getEncoded());

    }

    @Test
    public void testGetResponseBuilderForIR() {
        ipWithWaitResponseBuilder = responseBuilderFactoryImpl.getResponseBuilder(pKIRequestMessage);
        assertThat(ipWithWaitResponseBuilder, instanceOf(ResponseBuilder.class));
    }

    @Test
    public void testGetResponseBuilderForKUR() throws IOException {
        keyUpdateWithWaitResponseBuilder = responseBuilderFactoryImpl.getResponseBuilder(pKIKURMessage);
        assertThat(keyUpdateWithWaitResponseBuilder, instanceOf(ResponseBuilder.class));
    }

    @Test
    public void testGetResponseBuilderForPollRequest() throws IOException {
        pollResponseBuilder = responseBuilderFactoryImpl.getResponseBuilder(pKIPollRequestMessage);
        assertThat(pollResponseBuilder, instanceOf(ResponseBuilder.class));
    }

    @Test
    public void testGetResponseBuilderForCertConf() throws IOException {
        pkiConfResponseBuilder = responseBuilderFactoryImpl.getResponseBuilder(pKICertConfMessage);
        assertThat(pkiConfResponseBuilder, instanceOf(ResponseBuilder.class));
    }

}
