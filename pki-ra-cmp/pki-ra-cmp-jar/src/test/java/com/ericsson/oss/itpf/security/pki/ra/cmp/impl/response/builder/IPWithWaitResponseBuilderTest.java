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

import java.io.IOException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.IPWithWaitResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.ResponseBuilderTestUtil;

@RunWith(MockitoJUnitRunner.class)
public class IPWithWaitResponseBuilderTest {

    @InjectMocks
    IPWithWaitResponseBuilder ipWithWaitResponseBuilder;

    @Mock
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Mock
    ConfigurationParamsListener cMPConfigurationListener;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    CMPMessageEntity cMPMsgEntity;

    @Mock
    Logger logger;

    private static RequestMessage ipRequestmessage;
    private static ResponseMessage ipResponseMessage;
    private static String senderName;
    private static String transactionID = null;
    public static final String SENDER = "CN=issuer";
    private static String ISSUERNAME = "TestCA";

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage ipWaitingResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.IP_WITH_WAIT_RESPONSE).generate(pkiRequestMessage, responseParameters);

        ipResponseMessage = new IPWithWaitResponseMessage(ipWaitingResponseMessage.getEncoded());
        ipRequestmessage = new RequestMessage(pkiRequestMessage.getEncoded());
        ipRequestmessage.setIssuerName(ISSUERNAME);

        transactionID = ipRequestmessage.getBase64TransactionID();
        senderName = ipRequestmessage.getSenderName();

    }

    @Test
    public void testBuildResponse() throws Exception {
        setUpTestData();

        final byte[] response = ipWithWaitResponseBuilder.build(ipRequestmessage, transactionID);

        assertActualAndExpected(response);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testInitialConfigurationException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenThrow(new InvalidInitialConfigurationException());

        ipWithWaitResponseBuilder.build(ipRequestmessage, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testProtectionEncodingException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(SENDER);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new ProtectionEncodingException());

        ipWithWaitResponseBuilder.build(ipRequestmessage, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testInvalidInitialConfigurationException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(SENDER);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new InvalidInitialConfigurationException());

        ipWithWaitResponseBuilder.build(ipRequestmessage, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testIOException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(SENDER);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new IOException());

        ipWithWaitResponseBuilder.build(ipRequestmessage, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testResponseSignerException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(SENDER);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new ResponseSignerException());

        ipWithWaitResponseBuilder.build(ipRequestmessage, transactionID);
    }

    private void setUpTestData() throws IOException {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(SENDER);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenReturn(ipResponseMessage.toByteArray());
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(cMPMsgEntity);
    }

    private void assertActualAndExpected(final byte[] response) throws IOException {
        final PKIMessage expectedPKIMessage = ResponseBuilderTestUtil.pKIMessageFromByteArray(response);
        final PKIMessage actualPKIMessage = ipResponseMessage.getPKIResponseMessage();
        Mockito.verify(responseMessageSigningHelper).getSenderFromSignerCert(ISSUERNAME);
        Mockito.verify(responseMessageSigningHelper).signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject());
        ResponseBuilderTestUtil.assertCheck(expectedPKIMessage, actualPKIMessage);
    }

}
