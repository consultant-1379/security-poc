/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.handler;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.MarshalException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.RequestHandlerUtility;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.SignedResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.RevocationManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.revocation.event.publisher.RevocationServiceResponsePublisher;
import com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper.CertificateIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper.RevocationReasonTypeModelMapper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ JaxbUtil.class, CertificateUtility.class })
public class RevocationServiceRequestHandlerTest {

    @InjectMocks
    RevocationServiceRequestHandler revocationServiceRequestHandler;

    @Mock
    RevocationRequest revocationRequest;

    @Mock
    NodeList nodeListcert;

    @Mock
    SignedRevocationServiceRequest signedRevocationServiceRequest;

    @Mock
    RequestHandlerUtility requestHandlerUtility;

    @Mock
    SignedResponseBuilder signedResponseBuilder;

    @Mock
    Document document;

    @Mock
    RevocationServiceResponsePublisher revocationServiceResponsePublisher;

    @Mock
    CertificateIdentifierModelMapper certificateIdentifierModelMapper;

    @Mock
    RevocationReasonTypeModelMapper revocationReasonTypeMapper;

    @Mock
    RevocationManagementLocalService revocationManagementLocalService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    Logger logger;

    @Mock
    X509Certificate requestSignerCertificate;

    @Mock
    Certificate certificateToValidate;

    @Mock
    Node node;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    CertificateManagementLocalService certificateManagementLocalService;

    private static CertificateIdentifier certificateIdentifier;
    private static String issuerName = "issuerName";
    private static String serialNumber = "101";
    private static String cert = "MIIDTjCCAjagAwIBAgIHMzT/j2HMiTANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApFTk1fT0FNX0NBMB4XDTE1MDkwNDA2NTMyM1oXDTIzMDkwNDA2NTMyM1owXjEWMBQGA1UECwwNQlVDSV9EVUFDX05BTTERMA8GA1UECgwIRVJJQ1NTT04xJDAiBgNVBAMMG3N2Yy0xLXBraXJhc2Vydl9DTVBSQVNFUlZFUjELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCFOyvy8ydqD7KPxsOEq9ldb3kvhq8hATKRONDJPGB8dvbGLtA2Xo6ZxT4+WaVCxCw+dTprfNivV6zwPspmXnuqhALAv1SCeeBCpUMJTVuwzrsc/BqEefx2AKjdiwur1U+VPnAV2GV1Lo2kM50g98SYDyJOOpobCq4bhvbuxKN8kFHrw0LGF/E7hwBr5T8r1kPCdt3aYSMvmxMGi7gFp8rjuRvg3VoFJIrJtSay6JPyj2y+KPbCjG3BTvuDlWeW47/wV4R9RDjRYpdotleHrJMRx+Q691iPAI4kI19k2eO9b0ERvmZ7MXV1fEgc53+8kBu6MRmOSCx0r0kg9CS4l2yFAgMBAAGBAgeAggIHgKNSMFAwHwYDVR0jBBgwFoAU50al/zFguKBGt+HN15zsIlDilUMwHQYDVR0OBBYEFMQ8QZH6opu9xacTGsLulGHyrkY0MA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAQEAdCOZ1TSRH2yXmkrTBvFnTeh/VAohqTMfbKyixs/V3scID9Hm3CHB9FLptmZFAg5dnLWq790uzYUop+zXvJh/kQDjnEmt2P5MsDLOrZKPi/GjtYA2qUxgp01AFVO+VqgwTC65JLXNzkbW9djlsD2zeujTCgOuH/8XO+y/DV2VsnfV6eiYvchx/6kWnow9cBu5OTzNiwJ0Qe4IY82VWfiWob0F/0iAjg57H5VMWMq3Ypsim4/3lcyBDmUJuOMIqF5RFU+BoXfsFE67wdjX6Dsz5CQvAt+DU5cdROHKLRwf+Uh1gZfxD972VUFpu6h4Ei2omm+jOqnV5LJ/CNQqrZzkMQ==";

    @Test
    public void testHandle() throws CertificateException, IOException {
        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();

        setX509CerificateEncode();
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(requestSignerCertificate);
        Mockito.when(certificatePersistenceHelper.getCertificate(requestSignerCertificate)).thenReturn(certificateToValidate);
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");

        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    @Test
    public void testHandleForExpiredCertificateException() {
        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        setX509CerificateEncode();
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);

        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
    }

    @Test
    public void testHandleforInvalidInitialConfigurationException() {
        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenThrow(CredentialsManagementServiceException.class);
        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    @Test
    public void testHandleforInitialConfigurationException1() {
        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        setX509CerificateEncode();

        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");
        Date invalidityDate = new Date();
        RevocationReason revocationReason = RevocationReason.AFFILIATION_CHANGED;
        String transactionID = "100111";
        String senderName = "subjectName";
        Mockito.doThrow(RevokedCertificateException.class).when(revocationManagementLocalService).revokeCertificate(certificateIdentifier, invalidityDate, revocationReason, transactionID, senderName);
        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    @Test
    public void testHandleforDigitalSigningFailedException() {

        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        setX509CerificateEncode();

        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");
        Mockito.when(signedResponseBuilder.buildSignedRevocationResponse((RevocationResponse) Matchers.anyObject())).thenThrow(new DigitalSigningFailedException("DigitalSigningFailedException"));
        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    @Test
    public void testHandleforCredentialsManagementServiceException() throws CertificateException, IOException {

        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(requestSignerCertificate);
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificatePersistenceHelper.getCertificate(requestSignerCertificate)).thenReturn(certificateToValidate);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");

        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenThrow(CredentialsManagementServiceException.class);
        Mockito.when(document.getElementsByTagName("X509Certificate")).thenReturn(nodeListcert);
        Mockito.when(nodeListcert.item(0)).thenReturn(node);
        Mockito.when(nodeListcert.item(0).getFirstChild()).thenReturn(node);
        Mockito.when(nodeListcert.item(0).getFirstChild().getTextContent()).thenReturn(cert);

        // Mockito.when(certificateChainValidator.validateSignerCertificateAndChain((java.security.cert.X509Certificate)Matchers.anyObject())).th

        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    @Test
    public void testHandleforMarshalException() throws CertificateException, IOException {

        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        setX509CerificateEncode();
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(requestSignerCertificate);
        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");
        Mockito.when(signedResponseBuilder.buildSignedRevocationResponse((RevocationResponse) Matchers.anyObject())).thenThrow(new MarshalException("MarshalException"));
        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    @Test
    public void testHandleforExpiredCertificateException() throws CertificateException, IOException {

        setRevocationServiceRequestXMLData();
        setCertificateIdentifier();
        setX509CerificateEncode();

        Mockito.when(requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest())).thenReturn(document);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(CertificateUtility.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument(document)).thenReturn(requestSignerCertificate);
        Mockito.when((RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class)).thenReturn(revocationRequest);
        Mockito.when(certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest)).thenReturn(certificateIdentifier);
        Mockito.when(revocationReasonTypeMapper.fromModel(revocationRequest)).thenReturn(RevocationReason.SUPERSEDED);
        Mockito.when(revocationRequest.getInvalidityDate()).thenReturn("2015-02-02");
        // Mockito.when(signedResponseBuilder.buildSignedRevocationResponse((RevocationResponse) Matchers.anyObject())).thenThrow(new MarshalException("MarshalException"));
        Mockito.doThrow(ExpiredCertificateException.class)
                .when(revocationManagementLocalService)
                .revokeCertificate((CertificateIdentifier) Matchers.anyObject(), (Date) Matchers.anyObject(), (RevocationReason) Matchers.anyObject(), (String) Matchers.anyObject(),
                        (String) Matchers.anyObject());
        revocationServiceRequestHandler.handle(signedRevocationServiceRequest);
        Mockito.verify(requestHandlerUtility).loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
    }

    private void setRevocationServiceRequestXMLData() {
        revocationRequest.setInvalidityDate(new Date() + "");
        revocationRequest.setIssuerName("issuerName");
        revocationRequest.setSerialNumber(serialNumber);
        revocationRequest.setSubjectName("subjectName");
        revocationRequest.setTransactionId("100111");

    }

    private static void setCertificateIdentifier() {

        certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName("issuerName");
        certificateIdentifier.setSerialNumber("11011");

    }

    private void setX509CerificateEncode() {
        Mockito.when(document.getElementsByTagName("X509Certificate")).thenReturn(nodeListcert);
        Mockito.when(nodeListcert.item(0)).thenReturn(node);
        Mockito.when(nodeListcert.item(0).getFirstChild()).thenReturn(node);
        Mockito.when(nodeListcert.item(0).getFirstChild().getTextContent()).thenReturn(cert);
    }

}
