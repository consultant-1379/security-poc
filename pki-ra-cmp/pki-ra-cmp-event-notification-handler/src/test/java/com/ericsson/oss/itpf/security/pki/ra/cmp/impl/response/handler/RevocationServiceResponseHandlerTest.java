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

package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.UnmarshalException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.PKIManagerResponseProcessor;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.handler.RevocationServiceResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ JaxbUtil.class, CertificateUtility.class })
public class RevocationServiceResponseHandlerTest {

    @InjectMocks
    RevocationServiceResponseHandler revocationServiceResponseHandler;

    @Mock
    SignedRevocationServiceResponse revocationServiceResponse;

    @Mock
    CMPMessageEntity protocolMessageEntity;

    @Mock
    CMPLocalService cmpLocalService;

    @Mock
    RevocationResponse revocationServiceResponseXMLData;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    PKIManagerResponseProcessor responseUtility;

    @Mock
    Document document;

    @Mock
    CMPResponse cMPResponseXMLData;

    @Mock
    X509Certificate managerSignerCertificate;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    private static RequestMessage pKIRequestMessage;
    private static String transactionID = null;
    private static String senderName = "issuer";

    @BeforeClass
    public static void initializeTestData() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage =
                RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());

        transactionID = pKIRequestMessage.getBase64TransactionID();

    }

    @Test
    public void testHandle() throws CertificateException, IOException {

        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE);
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(persistenceHandler).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
    }

    @Test
    public void testHandleForTrue() throws CertificateException, IOException {
        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(revocationServiceResponseXMLData.isRevoked()).thenReturn(true);
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(persistenceHandler).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
    }

    @Test
    public void testHandleForOldCertificate() throws CertificateException, IOException {
        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(revocationServiceResponseXMLData.isRevoked()).thenReturn(true);
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.REVOCATION_IN_PROGRESS_FOR_OLD_CERTIFICATE);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(persistenceHandler).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
    }

    @Test
    public void testHandleForNotEqual() throws CertificateException, IOException {

        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(revocationServiceResponseXMLData.isRevoked()).thenReturn(false);
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.DONE);
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(persistenceHandler).fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
    }

    @Test
    public void testHandleForInvalidInitialConfigurationException() {
        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenThrow(
                new InvalidInitialConfigurationException("INITIAL CONFIGURATION DATA IS NOT VALID"));

        revocationServiceResponseHandler.handle(revocationServiceResponse);

        Mockito.verify(revocationServiceResponse).getRevocationServiceResponse();
    }

    @Test
    public void testHandleForDigitalSignatureValidationException() {
        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenThrow(new DigitalSignatureValidationException());
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(revocationServiceResponse).getRevocationServiceResponse();
    }

    @Test
    public void testHandleForUnmarshalException() {

        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenThrow(
                new UnmarshalException("ERROR OCCURED WHILE PARSING RESPONSE XML"));
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(revocationServiceResponse).getRevocationServiceResponse();
    }

    @Test
    public void testHandleForCertificateException() throws CertificateException, IOException {

        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(revocationServiceResponseXMLData.isRevoked()).thenReturn(false);
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.DONE);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenThrow(new CertificateException());
        revocationServiceResponseHandler.handle(revocationServiceResponse);
        Mockito.verify(revocationServiceResponse).getRevocationServiceResponse();
    }

    @Test
    public void testHandleForCertPathBuilderException() throws CertificateException, IOException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, CertPathBuilderException,
            KeyStoreException {

        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(revocationServiceResponseXMLData.isRevoked()).thenReturn(false);
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.DONE);
        revocationServiceResponseHandler.handle(revocationServiceResponse);
    }

    @Test
    public void testHandleForKeyStoreException() throws CertificateException, IOException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, CertPathBuilderException, KeyStoreException {

        final byte[] response = new byte[] { 1 };
        Mockito.when(revocationServiceResponse.getRevocationServiceResponse()).thenReturn(response);
        Mockito.when(responseUtility.loadAndValidateResponse(response)).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getObject(document, RevocationResponse.class)).thenReturn(revocationServiceResponseXMLData);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(managerSignerCertificate);
        Mockito.when(revocationServiceResponseXMLData.isRevoked()).thenReturn(false);
        Mockito.when(revocationServiceResponseXMLData.getTransactionID()).thenReturn(transactionID);
        Mockito.when(revocationServiceResponseXMLData.getSubjectName()).thenReturn(senderName);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getStatus()).thenReturn(MessageStatus.DONE);
        revocationServiceResponseHandler.handle(revocationServiceResponse);
    }

}
