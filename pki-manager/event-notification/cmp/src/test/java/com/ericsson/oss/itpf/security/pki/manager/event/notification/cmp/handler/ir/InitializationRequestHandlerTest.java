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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
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
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ResponseBuilderMockUtil;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er.ErrorResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception.ResponseEventBuilderException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher.CMPServiceResponsePublisher;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator.IAKValidationException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator.IAKValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(MockitoJUnitRunner.class)
public class InitializationRequestHandlerTest {

    @InjectMocks
    InitializationRequestHandler initializationRequestHandler;

    @Mock
    CMPCertificateManagementUtility cMPCertificateManagementUtility;

    @Mock
    CertificateManagementLocalService certificateManagementLocalService;

    @Mock
    InitializationResponseBuilder initializationResponseBuilder;

    @Mock
    IAKValidator iakValidator;

    @Mock
    CMPServiceResponsePublisher cMPServiceResponseDispatcher;

    @Mock
    ErrorResponseBuilder failureResponseBuilder;

    @Mock
    CMPCertificate cmpCertificate;

    @Mock
    CertificateFactory certificateFactory;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Certificate certificate;

    @Mock
    CMPResponse cMPResponse;

    @Mock
    SignedResponseBuilder requestHandlerUtility;

    @Mock
    Logger logger;

    @Mock
    SignedResponseBuilder signedResponseBuilder;

    @Mock
    EntityHandlerUtility entityHandlerUtility;

    @Mock
    static EntityCertificateManagementService endEntityCertificateManagementService;

    private static final String ERROR_MESSAGE = ErrorMessages.UNKNOWN_MESSAGE_TYPE;
    private static ResponseMessage pKIInitializationResponseMessage;
    private static RequestMessage pKIInitialisationRequestMessage;
    private static String transactionID = null;
    private static CMPRequest cMPRequestXMLData = null;
    private static IPResponseMessage iPResponseMessage = null;
    private static FailureResponseMessage failureResponseMessage = null;

    private static RequestMessage pKIInitializationRequestMessage;
    private static String rAKeyAndCertPath = null;
    private static CertDataHolder certDataHolder = null;
    private static CertificateRequest csr;

    static Certificate userCertificate;
    static List<Certificate> trustedCertificates;
    static CertificateChain certChain;
    static List<Certificate> certificatesFromDB;
    private static final String CANAME = "TestCA";

    @BeforeClass
    public static void prepareTestData() throws Exception {

        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage expectedPKIRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        Parameters responseParameters = AbstractMain.configureParameters(null);
        PKIMessage expectedPKIResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(expectedPKIRequestMessage, responseParameters);

        pKIInitialisationRequestMessage = new RequestMessage(expectedPKIRequestMessage.getEncoded());
        pKIInitializationResponseMessage = new IPResponseMessage(expectedPKIResponseMessage.getEncoded());
        transactionID = pKIInitialisationRequestMessage.getBase64TransactionID();
        setCMPRequestXMLData();
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        pKIInitializationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIInitializationRequestMessage.setIssuerName(CANAME);
        transactionID = pKIInitializationRequestMessage.getBase64TransactionID();
        rAKeyAndCertPath = InitializationResponseBuilderTest.class.getResource("/CertificatesTest/" + "racsa_omsas.jks").getPath();
        certDataHolder = CertDataHolder.getRACertDataHolder(rAKeyAndCertPath);
        csr = ResponseBuilderMockUtil.generateCSR(pKIInitializationRequestMessage.getPKIBody());
    }

    @Before
    public void setUpMocks() throws Exception {
        Certificate userCertificate = ResponseBuilderMockUtil.getUSerCertificate(certDataHolder);
        List<X509Certificate> trustedCertificates = ResponseBuilderMockUtil.getX509TrsutedCertificates(userCertificate);
        // CertificateChain certChain = ResponseBuilderMockUtil.getCertificateChain(trustedCertificates);

        Mockito.when(cMPCertificateManagementUtility.getUserCertificate(Matchers.anyString(), Matchers.<CertificateRequest> anyObject())).thenReturn(x509Certificate);
        Mockito.when(cMPCertificateManagementUtility.getCertificateChain(Matchers.anyString())).thenReturn(trustedCertificates);
        Mockito.when(cMPCertificateManagementUtility.getTrustCertificates(Matchers.anyString())).thenReturn(trustedCertificates);
    }

    @Test
    public void testHandle() throws Exception {
        Certificate userCertificate = ResponseBuilderMockUtil.getUSerCertificate(certDataHolder);
        List<X509Certificate> trustedCertificates = ResponseBuilderMockUtil.getX509TrsutedCertificates(userCertificate);
        // CertificateChain certChain = ResponseBuilderMockUtil.getCertificateChain(trustedCertificates);
        iPResponseMessage = new IPResponseMessage(pKIInitializationResponseMessage.toByteArray());
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(iPResponseMessage);
        Mockito.when(cMPCertificateManagementUtility.getUserCertificate(Matchers.anyString(), Matchers.<CertificateRequest> anyObject())).thenReturn(x509Certificate);
        Mockito.when(cMPCertificateManagementUtility.getCertificateChain(Matchers.anyString())).thenReturn(trustedCertificates);

        initializationRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(initializationResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());
    }

    @Test
    public void testHandle_ForIAKRequestMessage() throws Exception {
        setUpMocks();
        Parameters parameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        pKIInitialisationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        iPResponseMessage = new IPResponseMessage(pKIInitializationResponseMessage.toByteArray());
        setCMPRequestXMLData();
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(iPResponseMessage);
        initializationRequestHandler.handle(cMPRequestXMLData);

        Mockito.verify(initializationResponseBuilder).build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                Matchers.<X509Certificate> anyList());

    }

    @Test
    public void testHandle_ForIAKValidationException() throws Exception {
        setUpMocks();
        String entityName = "Entity";
        List<Certificate> certificatesFromDB = new ArrayList<Certificate>();
        certificatesFromDB.add(certificate);

        Parameters parameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        pKIInitialisationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        failureResponseMessage = new FailureResponseMessage(pKIInitialisationRequestMessage, ERROR_MESSAGE);
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);
        setCMPRequestXMLData();
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(iPResponseMessage);
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow(new CertificateServiceException());
        Mockito.when(cMPCertificateManagementUtility.getUserCertificate(Matchers.anyString(), Matchers.<CertificateRequest> anyObject())).thenThrow(new IAKValidationException());

        Mockito.when(certificateManagementLocalService.getEntityCertificates(entityName)).thenReturn(certificatesFromDB);

        initializationRequestHandler.handle(cMPRequestXMLData);

    }

    @Test
    public void testHandle_ForIOException() throws Exception {
        setUpMocks();
        String entityName = "Entity";
        List<Certificate> certificatesFromDB = new ArrayList<Certificate>();
        certificatesFromDB.add(certificate);
        byte[] response = new byte[] { 1 };

        Parameters parameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        pKIInitialisationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        failureResponseMessage = new FailureResponseMessage(pKIInitialisationRequestMessage, ERROR_MESSAGE);
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);
        setCMPRequestXMLData();
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(iPResponseMessage);
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow(new CertificateServiceException());
        Mockito.when(cMPCertificateManagementUtility.getUserCertificate(Matchers.anyString(), Matchers.<CertificateRequest> anyObject())).thenThrow(
                new ResponseEventBuilderException("ResponseEventBuilderException"));
        Mockito.when(signedResponseBuilder.buildSignedCMPResponse((CMPResponse) Matchers.anyObject())).thenReturn(response);
        Mockito.when(certificateManagementLocalService.getEntityCertificates(entityName)).thenReturn(certificatesFromDB);

        initializationRequestHandler.handle(cMPRequestXMLData);

    }

    @Test
    public void testHandle_PersistenceException() throws Exception {
        setUpMocks();
        String entityName = "Entity";
        List<Certificate> certificatesFromDB = new ArrayList<Certificate>();
        certificatesFromDB.add(certificate);

        Parameters parameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        pKIInitialisationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        failureResponseMessage = new FailureResponseMessage(pKIInitialisationRequestMessage, ERROR_MESSAGE);
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);
        setCMPRequestXMLData();
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(iPResponseMessage);
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow(new CertificateServiceException());

        Mockito.when(certificateManagementLocalService.getEntityCertificates(entityName)).thenThrow(new PersistenceException());

        initializationRequestHandler.handle(cMPRequestXMLData);

    }

    @Test
    public void testHandle_ForException() throws Exception {
        setUpMocks();
        String entityName = "Entity";
        List<Certificate> certificatesFromDB = new ArrayList<Certificate>();
        certificatesFromDB.add(certificate);
        byte[] response = new byte[] { 1 };

        Parameters parameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(parameters, null);
        pKIInitialisationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        failureResponseMessage = new FailureResponseMessage(pKIInitialisationRequestMessage, ERROR_MESSAGE);
        Mockito.when(failureResponseBuilder.build(Matchers.anyString(), Matchers.anyString(), Matchers.<RequestMessage> anyObject(), Matchers.<X509Certificate> anyObject())).thenReturn(
                failureResponseMessage);
        setCMPRequestXMLData();
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenReturn(iPResponseMessage);
        Mockito.when(
                initializationResponseBuilder.build(Matchers.<RequestMessage> anyObject(), Matchers.anyString(), Matchers.<X509Certificate> anyObject(), Matchers.<X509Certificate> anyList(),
                        Matchers.<X509Certificate> anyList())).thenThrow(new CertificateServiceException());
        Mockito.when(cMPCertificateManagementUtility.getUserCertificate(Matchers.anyString(), Matchers.<CertificateRequest> anyObject())).thenThrow(
                new ResponseEventBuilderException("ResponseEventBuilderException"));
        Mockito.when(signedResponseBuilder.buildSignedCMPResponse((CMPResponse) Matchers.anyObject())).thenReturn(response);
        Mockito.when(certificateManagementLocalService.getEntityCertificates(entityName)).thenThrow(Exception.class);
        initializationRequestHandler.handle(cMPRequestXMLData);

    }

    private static void setCMPRequestXMLData() {
        byte[] cMPRequest = pKIInitialisationRequestMessage.toByteArray();

        cMPRequestXMLData = new CMPRequest();
        cMPRequestXMLData.setCmpRequest(cMPRequest);
        cMPRequestXMLData.setTransactionId(transactionID);

    }

}
