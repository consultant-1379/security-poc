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
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CertConfStatusUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.instrumentation.CMPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.RevocationHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.RevocationHelper;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CertConfStatusUtil.class)
public class PKIConfResponseBuilderTest {

    @InjectMocks
    PKIConfResponseBuilder pKIConfResponseBuilder;

    @Mock
    PersistenceHandler persistanceHandler;

    @Mock
    CMPMessageEntity protocolMessageEntity;

    @Mock
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Mock
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Mock
    CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Mock
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    RevocationHelper revocationHelper;

    @Mock
    CMPInstrumentationBean cmpInstrumentationBean;

    @Mock
    RevocationHandler revocationHandler;

    private static RequestMessage pKICertConfRequestmessage;
    public static final String sender = "CN=issuer";
    private static String transactionID = null;
    private static String senderName;
    static PKIMessage pkiRequestMessage;
    private static String ISSUERNAME = "TestCA";

    @BeforeClass
    public static void prepareCertConfRequestMessage() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        Parameters responseParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);

        PKIMessage pkiCertConfRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        pKICertConfRequestmessage = new RequestMessage(pkiCertConfRequestMessage.getEncoded());
        pKICertConfRequestmessage.setIssuerName(ISSUERNAME);

        transactionID = pKICertConfRequestmessage.getBase64TransactionID();
        senderName = pKICertConfRequestmessage.getSenderName();

    }

    @Test
    public void testBuild() throws IOException {

        CMPMessageEntity messageEntity = new CMPMessageEntity();
        messageEntity.setRequestType(RequestType.KEY_UPDATE_REQUEST.toString());
        messageEntity.setInitialMessage(pkiRequestMessage.getEncoded());
        MessageStatus certConfStatus = MessageStatus.DONE;
        PowerMockito.mockStatic(CertConfStatusUtil.class);

        protocolMessageEntity.setRequestType(RequestType.KEY_UPDATE_REQUEST.toString());
        Mockito.when(persistanceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(messageEntity);

        Mockito.when(protocolMessageEntity.getInitialMessage()).thenReturn(pkiRequestMessage.getEncoded());
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn("CN=issuer");
        Mockito.when(CertConfStatusUtil.get(pKICertConfRequestmessage)).thenReturn(certConfStatus);

        pKIConfResponseBuilder.build(pKICertConfRequestmessage, transactionID);
        Mockito.verify(revocationHelper).updateRevocationStatus(pKICertConfRequestmessage);
    }

    @Test
    public void testBuildForRevoke() throws IOException {

        CMPMessageEntity messageEntity = new CMPMessageEntity();
        messageEntity.setRequestType(RequestType.KEY_UPDATE_REQUEST.toString());
        messageEntity.setResponseMessage(pkiRequestMessage.getEncoded());
        MessageStatus certConfStatus = MessageStatus.TO_BE_REVOKED;
        PowerMockito.mockStatic(CertConfStatusUtil.class);

        protocolMessageEntity.setRequestType(RequestType.KEY_UPDATE_REQUEST.toString());
        Mockito.when(persistanceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(messageEntity);

        Mockito.when(protocolMessageEntity.getResponseMessage()).thenReturn(pkiRequestMessage.getEncoded());
        Mockito.when(responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME)).thenReturn("CN=issuer");
        Mockito.when(CertConfStatusUtil.get(pKICertConfRequestmessage)).thenReturn(certConfStatus);

        pKIConfResponseBuilder.build(pKICertConfRequestmessage, transactionID);
        Mockito.verify(revocationHelper).updateRevocationStatus(pKICertConfRequestmessage);
    }

}
