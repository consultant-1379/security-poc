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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation;

import java.io.IOException;
import java.util.*;

import javax.naming.InvalidNameException;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CMPRequestSigner;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.dispatcher.RevocationServiceRequestDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.RevocationServiceRequestEvent;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CertificateUtility.class)
public class RevocationHandlerTest {

    @InjectMocks
    RevocationHandler revocationHandler;

    @Mock
    CMPMessageEntity protocolMessageEntity;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    RevocationServiceRequestEvent revocationServiceRequest;

    @Mock
    RevocationRequest revocationServiceRequestXMLData;

    @Mock
    CMPRequestSigner requestSigner;

    @Mock
    RevocationServiceRequestDispatcher revocationServiceRequestDispatcher;

    @Mock
    EventSender<RevocationServiceRequestEvent> revocationServiceRequestSender;

    @Mock
    Logger logger;

    private String certificateSerialNumber = "345df5787j";
    private Date modifiedDate = new Date();
    private Date modifyTime;
    private List<CMPMessageEntity> certificates = new ArrayList<CMPMessageEntity>();

    private static RequestMessage pKICertConfRequestmessage;
    private static String transactionId = null;
    private static String subjectName;
    static PKIMessage pkiRequestMessage;

    @BeforeClass
    public static void prepareCertConfRequestMessage() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        Parameters responseParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.INITIALIZATION_RESPONSE).generate(pkiRequestMessage, responseParameters);

        PKIMessage pkiCertConfRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.CERT_CONFIRM).generate(requestParameters, pkiResponseMessage);

        pKICertConfRequestmessage = new RequestMessage(pkiCertConfRequestMessage.getEncoded());

        transactionId = pKICertConfRequestmessage.getBase64TransactionID();
        subjectName = pKICertConfRequestmessage.getSenderName();

    }

    @Test
    public void testRevoke() throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException, IOException {
        modifyTime = new Date();
        byte[] signedXMLData = new byte[1];
        String issuerName = pKICertConfRequestmessage.getRecipientName();
        protocolMessageEntity.setModifyTime(modifyTime);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, subjectName)).thenReturn(protocolMessageEntity);
        Mockito.when(protocolMessageEntity.getModifyTime()).thenReturn(modifiedDate);
        Mockito.when(requestSigner.signRevocationRequest(revocationServiceRequestXMLData)).thenReturn(signedXMLData);
        revocationHandler.revoke(transactionId, subjectName, issuerName, certificateSerialNumber);
        Mockito.verify(persistenceHandler).fetchEntityByTransactionIdAndEntityName(transactionId, subjectName);
    }

    @Test
    public void testRevokeCertificateBasedOnStatus() throws IOException, MessageParsingException, InvalidNameException {

        byte[] messageFromDB = pkiRequestMessage.getEncoded();
        String issuerName = pKICertConfRequestmessage.getSenderName();

        certificates.add(protocolMessageEntity);

        Mockito.when(protocolMessageEntity.getResponseMessage()).thenReturn(messageFromDB);
        Mockito.when(protocolMessageEntity.getTransactionID()).thenReturn(transactionId);
        Mockito.when(protocolMessageEntity.getSenderName()).thenReturn(subjectName);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(CertificateUtility.getCertificateIssuer(messageFromDB)).thenReturn(issuerName);
        Mockito.when(CertificateUtility.getCertificateSerialNumber(messageFromDB)).thenReturn(certificateSerialNumber);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, subjectName)).thenReturn(protocolMessageEntity);

        Mockito.when(protocolMessageEntity.getModifyTime()).thenReturn(modifiedDate);
        Mockito.when(persistenceHandler.fetchToBeRevokedMessages(500)).thenReturn(certificates);
        revocationHandler.revokeCertificateBasedOnStatus();
        Mockito.verify(persistenceHandler).fetchToBeRevokedMessages(500);
    }

    @Test
    public void testRevokeCertificateBasedOnStatusException() throws IOException, MessageParsingException, InvalidNameException {

        byte[] messageFromDB = pkiRequestMessage.getEncoded();
        String issuerName = pKICertConfRequestmessage.getSenderName();

        certificates.add(protocolMessageEntity);

        Mockito.when(protocolMessageEntity.getResponseMessage()).thenReturn(messageFromDB);
        Mockito.when(protocolMessageEntity.getTransactionID()).thenReturn(transactionId);
        Mockito.when(protocolMessageEntity.getSenderName()).thenReturn(subjectName);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(CertificateUtility.getCertificateIssuer(messageFromDB)).thenReturn(issuerName);
        Mockito.when(CertificateUtility.getCertificateSerialNumber(messageFromDB)).thenReturn(certificateSerialNumber);
        Mockito.when(persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, subjectName)).thenReturn(protocolMessageEntity);

        Mockito.when(protocolMessageEntity.getModifyTime()).thenReturn(modifiedDate);
        Mockito.when(persistenceHandler.fetchToBeRevokedMessages(500)).thenReturn(certificates);
        Mockito.when(protocolMessageEntity.getResponseMessage()).thenThrow(new MessageParsingException());
        revocationHandler.revokeCertificateBasedOnStatus();
        Mockito.verify(persistenceHandler).fetchToBeRevokedMessages(500);
    }
}