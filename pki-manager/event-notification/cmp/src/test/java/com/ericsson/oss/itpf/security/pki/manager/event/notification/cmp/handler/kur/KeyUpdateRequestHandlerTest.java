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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.kur;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ResponseBuilderMockUtil;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er.ErrorResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception.ResponseEventBuilderException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir.InitializationResponseBuilderTest;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher.CMPServiceResponsePublisher;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator.IAKValidationException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;

@RunWith(MockitoJUnitRunner.class)
public class KeyUpdateRequestHandlerTest {

    @InjectMocks
    KeyUpdateRequestHandler keyUpdateRequestHandler;

    @Mock
    KeyUpdateResponseBuilder keyUpdateResponseBuilder;

    @Mock
    ErrorResponseBuilder failureResponseBuilder;

    @Mock
    CMPServiceResponsePublisher cMPServiceResponseDispatcher;

    @Mock
    CMPCertificateManagementUtility cMPCertificateManagementUtility;

    @Mock
    Logger logger;

    @Mock
    CertificateManagementLocalService certificateManagementLocalService;

    @Mock
    EntityHandlerUtility entityHandlerUtility;

    @Mock
    Certificate certificate;
    @Mock
    X509Certificate x509Certificate;
    @Mock
    SignedResponseBuilder requestHandlerUtility;

    private static RequestMessage keyUpdateRequestMessage;
    private static String transactionID = null;
    private static CMPRequest cMPRequestXMLData = null;
    private static KeyUpdateResponseMessage keyUpdateResponseMessage = null;
    private static FailureResponseMessage failureResponseMessage = null;
    private static String rAKeyAndCertPath = null;
    private static CertDataHolder certDataHolder = null;
    private static CertificateRequest csr;
    private static CMPResponse cMPResponseXMLData;
    static List<Certificate> certificatesFromDB;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage expectedPKIRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(requestParameters, null);
        Parameters responseParameters = AbstractMain.configureParameters(null);
        PKIMessage expectedPKIResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.KEY_UPDATE_RESPONSE).generate(expectedPKIRequestMessage, responseParameters);

        keyUpdateRequestMessage = new RequestMessage(expectedPKIRequestMessage.getEncoded());
        keyUpdateResponseMessage = new KeyUpdateResponseMessage(expectedPKIResponseMessage.getEncoded());
        failureResponseMessage = new FailureResponseMessage(keyUpdateRequestMessage, ErrorMessages.UNKNOWN_MESSAGE_TYPE);

        transactionID = keyUpdateRequestMessage.getBase64TransactionID();
        setCMPRequestXMLData();
    }

    public void setUpMocks() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(requestParameters, null);

        keyUpdateRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionID = keyUpdateRequestMessage.getBase64TransactionID();
        rAKeyAndCertPath = InitializationResponseBuilderTest.class.getResource("/CertificatesTest/" + "racsa_omsas.jks").getPath();
        certDataHolder = CertDataHolder.getRACertDataHolder(rAKeyAndCertPath);
        csr = ResponseBuilderMockUtil.generateCSR(keyUpdateRequestMessage.getPKIBody());
        Certificate userCertificate = ResponseBuilderMockUtil.getUSerCertificate(certDataHolder);
        List<X509Certificate> trustedCertificates = ResponseBuilderMockUtil.getX509TrsutedCertificates(userCertificate);

        Mockito.when(cMPCertificateManagementUtility.getUserCertificate(Matchers.anyString(), Matchers.<CertificateRequest> anyObject())).thenReturn(x509Certificate);
        Mockito.when(cMPCertificateManagementUtility.getCertificateChain(Matchers.anyString())).thenReturn(trustedCertificates);
        Mockito.when(cMPCertificateManagementUtility.getTrustCertificates(Matchers.anyString())).thenReturn(trustedCertificates);
    }

    @Test
    public void testHandle() throws Exception {
        setUpMocks();
        byte[] signedXMLData = keyUpdateRequestMessage.toByteArray();
        Mockito.when(
                keyUpdateResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(keyUpdateResponseMessage);
        Mockito.when(requestHandlerUtility.buildSignedCMPResponse(cMPResponseXMLData)).thenReturn(signedXMLData);

        keyUpdateRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(keyUpdateResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());
    }

    @Test
    public void testHandle_ForProtocolModelException() throws Exception {
        setUpMocks();
        Mockito.when(
                keyUpdateResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow((new ResponseEventBuilderException("Error")));
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);

        keyUpdateRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(keyUpdateResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());

    }

    @Test
    public void testHandle_ForIOException() throws Exception {
        setUpMocks();
        Mockito.when(
                keyUpdateResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow((new ResponseEventBuilderException("Error")));
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenThrow(
                new IOException());

        keyUpdateRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(keyUpdateResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());

    }

    @Test
    public void testHandle_ForException() throws Exception {
        setUpMocks();
        Mockito.when(
                keyUpdateResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow((new ResponseEventBuilderException()));
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenThrow(
                new IAKValidationException());

        keyUpdateRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(keyUpdateResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());

    }

    @Test
    public void testHandle_ForHandleException() throws Exception {
        setUpMocks();
        String entityName = "Entity";
        List<Certificate> certificatesFromDB = new ArrayList<Certificate>();
        certificatesFromDB.add(certificate);
        Mockito.when(
                keyUpdateResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow((new ResponseEventBuilderException("Error")));
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);

        Mockito.when(certificateManagementLocalService.getEntityCertificates(entityName)).thenReturn(certificatesFromDB);

        keyUpdateRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(keyUpdateResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());

    }

    private static void setCMPRequestXMLData() {
        byte[] cMPRequest = keyUpdateRequestMessage.toByteArray();

        cMPRequestXMLData = new CMPRequest();
        cMPRequestXMLData.setCmpRequest(cMPRequest);
        cMPRequestXMLData.setTransactionId(transactionID);
        cMPRequestXMLData.setCmpRequest(cMPRequest);

    }

}
