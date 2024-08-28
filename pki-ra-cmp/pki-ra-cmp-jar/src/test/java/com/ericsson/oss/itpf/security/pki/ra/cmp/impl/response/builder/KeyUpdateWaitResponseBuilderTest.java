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

import static org.mockito.Mockito.never;

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
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.KUPWithWaitResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.ResponseBuilderTestUtil;

@RunWith(MockitoJUnitRunner.class)
public class KeyUpdateWaitResponseBuilderTest {

    @InjectMocks
    KeyUpdateWaitResponseBuilder keyUpdateWaitResponseBuilder;

    @Mock
    ConfigurationParamsListener cMPConfigurationListener;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Mock
    CMPMessageEntity cMPMsgEntity;

    @Mock
    Logger logger;

    private static RequestMessage keyUpdateRequest;
    private static ResponseMessage keyUpdateResponse;
    private static String transactionID = null;
    private static String senderName;
    public static final String sender = "CN=issuer";
    private static String ISSUERNAME = "TestCA";

    @BeforeClass
    public static void prepareKeyUpdateRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(requestParameters, null);

        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.KEY_UPDATE_RESPONSE).generate(pkiRequestMessage, responseParameters);

        keyUpdateResponse = new KUPWithWaitResponseMessage(pkiResponseMessage.getEncoded());
        keyUpdateRequest = new RequestMessage(pkiRequestMessage.getEncoded());
        keyUpdateRequest.setIssuerName(ISSUERNAME);

        transactionID = keyUpdateRequest.getBase64TransactionID();
        senderName = keyUpdateRequest.getSenderName();

    }

    @Test
    public void testBuildResponse() throws Exception {

        setUpTestData();

        final byte[] response = keyUpdateWaitResponseBuilder.build(keyUpdateRequest, transactionID);

        assertActualAndExpected(response);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testInitialConfigurationException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenThrow(new InvalidInitialConfigurationException());

        keyUpdateWaitResponseBuilder.build(keyUpdateRequest, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testIOException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(sender);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new IOException());

        keyUpdateWaitResponseBuilder.build(keyUpdateRequest, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testProtectionEncodingException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(sender);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new ProtectionEncodingException());

        keyUpdateWaitResponseBuilder.build(keyUpdateRequest, transactionID);
    }

    @Test(expected = ResponseBuilderException.class)
    public void testResponseSignerException() throws Exception {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(sender);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenThrow(new ResponseSignerException());

        keyUpdateWaitResponseBuilder.build(keyUpdateRequest, transactionID);
    }

    private void assertActualAndExpected(final byte[] response) throws IOException {
        final PKIMessage expectedPKIMessage = ResponseBuilderTestUtil.pKIMessageFromByteArray(response);
        final PKIMessage actualPKIMessage = keyUpdateResponse.getPKIResponseMessage();
        ResponseBuilderTestUtil.assertCheck(expectedPKIMessage, actualPKIMessage);
    }

    private void setUpTestData() throws IOException {
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn(sender);
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<IPWithWaitResponseMessage> anyObject())).thenReturn(keyUpdateRequest.getPKIMessage().getEncoded());
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(cMPMsgEntity);
        Mockito.verify(responseMessageSigningHelper, never()).getSenderFromSignerCert(ISSUERNAME);
        Mockito.verify(responseMessageSigningHelper, never()).signMessage(Mockito.anyString(), Matchers.<KUPWithWaitResponseMessage> anyObject());
    }
}
