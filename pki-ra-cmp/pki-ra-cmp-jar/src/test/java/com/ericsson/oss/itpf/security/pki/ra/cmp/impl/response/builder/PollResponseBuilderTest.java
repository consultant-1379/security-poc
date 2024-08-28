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
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.PollResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.ResponseBuilderTestUtil;

@RunWith(MockitoJUnitRunner.class)
public class PollResponseBuilderTest {
    @InjectMocks
    PollResponseBuilder pollResponseBuilder;

    @Mock
    InitialConfiguration configurationData;

    @Mock
    ConfigurationParamsListener cMPConfigurationListener;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Mock
    CMPMessageEntity protocolMessageEntity;

    @Mock
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Mock
    CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Mock
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    @Mock
    Logger logger;

    private static RequestMessage pollRequestMessage;
    private static ResponseMessage pollResponseMessage;
    private static String transactionID = null;
    private static String senderName = null;
    private static String ISSUERNAME = "TestCA";

    @BeforeClass
    public static void preparePollRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiInitialResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);
        final PKIMessage pkiPollRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.POLL_REQUEST).generate(requestParameters, pkiInitialResponseMessage);
        final Parameters responseParameters1 = AbstractMain.configureParameters(null);
        final PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.POLL_RESPONSE).generate(pkiPollRequestMessage, responseParameters1);

        pollResponseMessage = new PollResponseMessage(pkiResponseMessage.getEncoded());
        pollRequestMessage = new RequestMessage(pkiPollRequestMessage.getEncoded());
        pollRequestMessage.setIssuerName(ISSUERNAME);
        transactionID = pollRequestMessage.getBase64TransactionID();
        senderName = pollRequestMessage.getSenderName();
    }

    @Test
    public void testBuildResponseForIP() throws Exception {

        setUpTestData();

        final byte[] response = pollResponseBuilder.build(pollRequestMessage, transactionID);

        assertActualAndExpected(response);
    }

    @Test
    public void testBuild() throws Exception {
        setUpTestDataForWaitForAck();
        final byte[] response = pollResponseBuilder.build(pollRequestMessage, transactionID);
        assertActualAndExpected(response);
    }

    @Test
    public void testBuildForToBeRevoked() throws Exception {
        setUpTestDataForToBeRevokedNew();
        final byte[] response = pollResponseBuilder.build(pollRequestMessage, transactionID);
        assertActualAndExpected(response);
    }

    private void setUpTestData() throws IOException {
        final CMPMessageEntity cMPMessageEntity = buildMessageEntityForSetUp();
        mockTestData(senderName, cMPMessageEntity);
    }

    private void setUpTestDataForWaitForAck() throws IOException {
        final CMPMessageEntity cMPMessageEntity = buildCMPMessageEntityForSetUp();
        mockTestData(senderName, cMPMessageEntity);
    }

    private void setUpTestDataForToBeRevokedNew() throws IOException {
        final CMPMessageEntity cMPMessageEntity = buildCMPMessageEntityForSignSetUp();
        mockTestData(senderName, cMPMessageEntity);
    }

    private void assertActualAndExpected(final byte[] response) throws IOException {
        final PKIMessage expectedPKIMessage = ResponseBuilderTestUtil.pKIMessageFromByteArray(response);
        final PKIMessage actualPKIMessage = pollResponseMessage.getPKIResponseMessage();
        ResponseBuilderTestUtil.assertCheck(expectedPKIMessage, actualPKIMessage);
    }

    private void mockTestData(final String senderName, final CMPMessageEntity cMPMessageEntity) throws IOException {
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(cMPMessageEntity);
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn("CN=issuer");
        Mockito.when(responseMessageSigningHelper.signMessage(Mockito.anyString(), Matchers.<ResponseMessage> anyObject())).thenReturn(pollRequestMessage.getPKIMessage().getEncoded());
    }

    private CMPMessageEntity buildMessageEntityForSetUp() throws IOException {
        final CMPMessageEntity cMPMessageEntity = new CMPMessageEntity();
        cMPMessageEntity.setResponseMessage(pollResponseMessage.toByteArray());
        cMPMessageEntity.setStatus(MessageStatus.NEW);
        return cMPMessageEntity;
    }

    private CMPMessageEntity buildCMPMessageEntityForSetUp() throws IOException {
        final CMPMessageEntity cMPMessageEntity = new CMPMessageEntity();
        cMPMessageEntity.setResponseMessage(pollResponseMessage.toByteArray());
        cMPMessageEntity.setStatus(MessageStatus.WAIT_FOR_ACK);
        cMPMessageEntity.setTransactionID(transactionID);
        return cMPMessageEntity;
    }

    private CMPMessageEntity buildCMPMessageEntityForSignSetUp() throws IOException {
        final CMPMessageEntity cMPMessageEntity = new CMPMessageEntity();
        cMPMessageEntity.setResponseMessage(pollResponseMessage.toByteArray());
        cMPMessageEntity.setStatus(MessageStatus.TO_BE_REVOKED_NEW);
        cMPMessageEntity.setTransactionID(transactionID);
        return cMPMessageEntity;
    }
}
