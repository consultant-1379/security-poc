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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import javax.persistence.*;

import org.bouncycastle.util.encoders.Base64;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DOMException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.XMLException;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateChainCRLValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateRevokeValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api.SCEPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;
import com.ericsson.oss.itpf.security.pki.ra.scep.response.processor.ResponseProcessor;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * This class tests ResponseProcessor
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ JaxbUtil.class, CertificateUtility.class, DOMUtil.class })
public class ResponseProcessorTest {

    @Mock
    private EntityManager entityManager;
    @Mock
    private EntityTransaction transaction;
    @InjectMocks
    private ResponseProcessor responseProcessor;
    @Mock
    private Pkcs7ScepRequestEntity pkcs7ScepRequestEntity;
    @Mock
    private Logger logger;
    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    ScepResponse scepResp;

    @Mock
    Document document;

    @Mock
    private CryptoService cryptoService;
    @Mock
    private ConfigurationListener configurationListener;
    @Mock
    private DigitalSignatureValidator digitalSignatureValidator;

    private SignedScepResponseMessage signedScepResponseMessage;
    @Mock
    private ScepCrlCacheUtil scepCrlCacheUtil;
    @Mock
    private CertificateChainCRLValidator certificateChainCRLValidator;
    @Mock
    private CertificateRevokeValidator certificateRevokeValidator;

    @Mock
    private SCEPLocalService scepLocalService;

    private String scepResponse = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHNjZXBSZXNwb25zZT48Y2VydGlmaWNhdGU+TUlJRCtUQ0NBdUdnQXdJQkFnSUVKRzIxRURBTkJna3Foa2lHOXcwQkFRVUZBREF4TVJFd0R3WURWUVFLREFoRmNtbGpjM052YmpFY01Cb0dBMVVFQXd3VFRGUkZTVkJUWldOT1JXTjFjMUp2YjNSRFFUQWVGdzB4TkRFeE1EVXdOakk1TWpkYUZ3MHhPVEV4TURNeE1qSTVNakZhTUM0eExEQXFCZ05WQkFNTUkweFVSVWxRVTJWalRrVmpkWE5oZEdOc2RtMHhNREkwVTJObGNGSmhVMlZ5ZG1WeU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcHV1QUdabXZzVjladmxYeW15QzZPVC9nL3h5L25MVURPTE5nOCs1YVB6NlZTL0d5SE9hbGJXK2hyeHdSUWYyUlNETlByaFoxTHF2bWh0MUpPR1Z5QUVHR0E0cktXODV3YUFxbCs2a0U4STZYRjUvWGJ4Szl4M3Q3MWJ6cFdWRlVvQk1hNkMxQTRMYk9ETDZucEw2OFJpdVFCK3I4SzJlcDNIV1M2bjZlZVc2UTJZdVU0bUsvRFFpeFVzdGp0bXBJWkdRbWVqZkdIb0hrS2E5dkRqeEpYeXp0RTlkUHZSZUZMVFV2TXFvckpwc0RHVzNPREUvRWFNY0FrRjBneVIvcmRFUFNUWUtEd1NwR1d3bTl4MVcxUkROSmdrY3Y4d3o2Q1h4YXdpSG9haVpiQVVHZ01nbU9lTlhGTDU2VDBuenN2YjZvNlk5TDR6OWQwdmdjSlJPbzB3SURBUUFCbzRJQkdqQ0NBUll3SFFZRFZSME9CQllFRlBpU0wvM2VZOTVyUGFBSTZPWW9NWTlBdEZhZU1Bd0dBMVVkRXdFQi93UUNNQUF3SHdZRFZSMGpCQmd3Rm9BVWt1ZU9KUEl3M1M4L2RZZmllV2NzaEVXS0R6Z3dnYlVHQTFVZEh3U0JyVENCcWpCVG9GR2dUNFpOYUhSMGNEb3ZMMk5rY0RFdVkyUndjeTVoZEdoMFpXMHVaV1ZwTG1WeWFXTnpjMjl1TG5ObE9qSXpOemN2YVc1MFpYSnVZV3d2VEZSRlNWQlRaV05PUldOMWMxSnZiM1JEUVM1amNtd3dVNkJSb0UrR1RXaDBkSEE2THk5alpIQXlMbU5rY0hNdVlYUm9kR1Z0TG1WbGFTNWxjbWxqYzNOdmJpNXpaVG95TXpjM0wybHVkR1Z5Ym1Gc0wweFVSVWxRVTJWalRrVmpkWE5TYjI5MFEwRXVZM0pzTUE0R0ExVWREd0VCL3dRRUF3SURxREFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBTzQwYzVCVEpaTDlmUVhxZ2JqV0dmTjlLYWtWK1QrV2phb2NyVUc2Y0swNFpIdGozeDFja3RkSS83N0xtc0k5eHB1T0tRZlZtTWUwSmdoWTlxQmxTbzBXMk02TFV5cHNEYXBBQVlTRmZoODhkdHdHT0drbGtTb0dLREJPRDNkcXVNMDIvdnFqZmZhN0MzWXUvekJINTJwekcraDhTeUVSZ21Wb3RLNnBPbC95UjZxeEYycUJ4dWsraTNoU3NqQlV1QTFSS2NlaFFRbnUxQWcwUmNwR3puQUg0Qm84MnBYOFltUHc0WFh3VmlzcHQ3TG5MNmZWM0o5MnRHRDRJelJzbjlKRUNYRWpGR21GUmtzYkI4RXdFY3FFWEpJQ0hPYzJjUDFSS05Wd3BRWkN0TFpVY0xGOU1YTkNFSk9qNFBscDYvSUg0dmF0eGRWWXBNR28rQkY2QmdRPT08L2NlcnRpZmljYXRlPjxzdGF0dXM+MDwvc3RhdHVzPjx0cmFuc2FjdGlvbklkPjEyPC90cmFuc2FjdGlvbklkPjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMjAwMS9SRUMteG1sLWMxNG4tMjAwMTAzMTUiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PERpZ2VzdFZhbHVlPjJTUjB3MXdoWGtMUU1Tb0lUMEhxZWhsUElLQ1Qyb2Fib3dEWDdSb2gxdEU9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8+PFNpZ25hdHVyZVZhbHVlPmN0TXBUdGpHblJWT0lmMWdkRmV2bFcwQ2FmblE0cndETS9mVzFJS1k1eGlycDR1WGFDMUF1ZlhGTkM0dVlWbDV1NmhhMlBheGI0RjENCnduNGh5bFdIK2JDSitQcWZhcFgxakNjaXVuV1p5M0VGOGF5OUJib1lDV1ZLbDRrajErRFhKamZBdjFWMnVSY0tZa05nZ0FlQ001LzINCk9HK1dwV3hYcll2Nm80enZBcGsvaDhRaDNmQ1l6b3BrTjRFMnVKa05VT0dCWk5GaVRpQW9tQldsVUxmdjU1bkZBdE1qb2cvUzRrVWMNCkp3K0xzczlOMjRHeWgwa0pGZWExeG1TS1UydWtkcklaZmQxRGc5dTJLc1RveGxmK2sxbVQvbC9WV2V0bitlNzhGK3h5Vm5rTEc1dEYNCllyNDU3MVhKV0FBakZLSEhGbWpkNVVUZzMzaUR1bVBwUmJJZnF3PT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUQrVENDQXVHZ0F3SUJBZ0lFSkcyMUVEQU5CZ2txaGtpRzl3MEJBUVVGQURBeE1SRXdEd1lEVlFRS0RBaEZjbWxqYzNOdmJqRWMNCk1Cb0dBMVVFQXd3VFRGUkZTVkJUWldOT1JXTjFjMUp2YjNSRFFUQWVGdzB4TkRFeE1EVXdOakk1TWpkYUZ3MHhPVEV4TURNeE1qSTUNCk1qRmFNQzR4TERBcUJnTlZCQU1NSTB4VVJVbFFVMlZqVGtWamRYTmhkR05zZG0weE1ESTBVMk5sY0ZKaFUyVnlkbVZ5TUlJQklqQU4NCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXB1dUFHWm12c1Y5WnZsWHlteUM2T1QvZy94eS9uTFVET0xOZzgrNWENClB6NlZTL0d5SE9hbGJXK2hyeHdSUWYyUlNETlByaFoxTHF2bWh0MUpPR1Z5QUVHR0E0cktXODV3YUFxbCs2a0U4STZYRjUvWGJ4SzkNCngzdDcxYnpwV1ZGVW9CTWE2QzFBNExiT0RMNm5wTDY4Uml1UUIrcjhLMmVwM0hXUzZuNmVlVzZRMll1VTRtSy9EUWl4VXN0anRtcEkNClpHUW1lamZHSG9Ia0thOXZEanhKWHl6dEU5ZFB2UmVGTFRVdk1xb3JKcHNER1czT0RFL0VhTWNBa0YwZ3lSL3JkRVBTVFlLRHdTcEcNCld3bTl4MVcxUkROSmdrY3Y4d3o2Q1h4YXdpSG9haVpiQVVHZ01nbU9lTlhGTDU2VDBuenN2YjZvNlk5TDR6OWQwdmdjSlJPbzB3SUQNCkFRQUJvNElCR2pDQ0FSWXdIUVlEVlIwT0JCWUVGUGlTTC8zZVk5NXJQYUFJNk9Zb01ZOUF0RmFlTUF3R0ExVWRFd0VCL3dRQ01BQXcNCkh3WURWUjBqQkJnd0ZvQVVrdWVPSlBJdzNTOC9kWWZpZVdjc2hFV0tEemd3Z2JVR0ExVWRId1NCclRDQnFqQlRvRkdnVDRaTmFIUjANCmNEb3ZMMk5rY0RFdVkyUndjeTVoZEdoMFpXMHVaV1ZwTG1WeWFXTnpjMjl1TG5ObE9qSXpOemN2YVc1MFpYSnVZV3d2VEZSRlNWQlQNClpXTk9SV04xYzFKdmIzUkRRUzVqY213d1U2QlJvRStHVFdoMGRIQTZMeTlqWkhBeUxtTmtjSE11WVhSb2RHVnRMbVZsYVM1bGNtbGoNCmMzTnZiaTV6WlRveU16YzNMMmx1ZEdWeWJtRnNMMHhVUlVsUVUyVmpUa1ZqZFhOU2IyOTBRMEV1WTNKc01BNEdBMVVkRHdFQi93UUUNCkF3SURxREFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBTzQwYzVCVEpaTDlmUVhxZ2JqV0dmTjlLYWtWK1QrV2phb2NyVUc2Y0swNFoNCkh0ajN4MWNrdGRJLzc3TG1zSTl4cHVPS1FmVm1NZTBKZ2hZOXFCbFNvMFcyTTZMVXlwc0RhcEFBWVNGZmg4OGR0d0dPR2tsa1NvR0sNCkRCT0QzZHF1TTAyL3ZxamZmYTdDM1l1L3pCSDUycHpHK2g4U3lFUmdtVm90SzZwT2wveVI2cXhGMnFCeHVrK2kzaFNzakJVdUExUksNCmNlaFFRbnUxQWcwUmNwR3puQUg0Qm84MnBYOFltUHc0WFh3VmlzcHQ3TG5MNmZWM0o5MnRHRDRJelJzbjlKRUNYRWpGR21GUmtzYkINCjhFd0VjcUVYSklDSE9jMmNQMVJLTlZ3cFFaQ3RMWlVjTEY5TVhOQ0VKT2o0UGxwNi9JSDR2YXR4ZFZZcE1HbytCRjZCZ1E9PTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2NlcFJlc3BvbnNlPg==";
    private X509Certificate certificate = null;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     * 
     * @throws UnrecoverableKeyException
     * @throws CertificateEncodingException
     */
    @Before
    public void setUp() throws UnrecoverableKeyException, CertificateEncodingException {
        signedScepResponseMessage = new SignedScepResponseMessage();
        byte[] responseArray = scepResponse.getBytes();
        if (StringUtility.isBase64(new String(responseArray))) {
            responseArray = Base64.decode(responseArray);
        }
        signedScepResponseMessage.setScepResponse(Base64.decode(scepResponse));
        certificate = (X509Certificate) new ResponseProcessorTest().getCertificate();
    }

    private Certificate getCertificate() {
        java.security.cert.Certificate cert = null;

        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
            keyStore.load(ResponseProcessorTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());
            cert = keyStore.getCertificate(JUnitConstants.caName);

        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
        return cert;
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     * 
     * @throws IOException
     * @throws CertificateException
     * @throws DOMException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest() throws DOMException, CertificateException, IOException {
        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doNothing().when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        // Mockito.verify(logger).info("End of validate signature on the SCEP XML Response");

        PowerMockito.mockStatic(CertificateUtility.class);
        certificate = (X509Certificate) cryptoService.readCertificate(JUnitConstants.caName, false);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(DOMUtil.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument((Document) Mockito.any())).thenReturn(certificate);
        Mockito.when(DOMUtil.getDocument((byte[]) Matchers.any())).thenReturn(document);
        Mockito.when(JaxbUtil.getObject(document, ScepResponse.class)).thenReturn(scepResp);
        Mockito.when(scepResp.getTransactionId()).thenReturn("001");
        Mockito.when(CertificateUtility.getIssuerName(certificate)).thenReturn(JUnitConstants.caName);
        X509CRL issuerCRL = null;
        Mockito.when(scepCrlCacheUtil.getCRL(JUnitConstants.caName)).thenReturn(issuerCRL);
        responseProcessor.processResponse(signedScepResponseMessage);
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_DigitalSignatureValidationException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(new DigitalSignatureValidationException()).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);

        Mockito.verify(logger).error("Digital signature validation failed on response message");
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_XMLUtilityException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(new XMLException("Failed to marshal the xml document")).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);

        Mockito.verify(logger).error("Failed to marshal the xml document");
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_PersistenceException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(new XMLException("Failed to marshal the xml document")).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());
        Mockito.doThrow(new PersistenceException()).when(transaction).commit();

        responseProcessor.processResponse(signedScepResponseMessage);

    }

    @Test
    public void testprocessRequest_NullScepResponseByteArray() {
        final SignedScepResponseMessage scepResponseMsg = new SignedScepResponseMessage();
        responseProcessor.processResponse(scepResponseMsg);
        Mockito.verify(logger).error(ErrorMessages.INVALID_SCEP_RESPONSE);
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_scepResponseMessage_null() {

        signedScepResponseMessage.setScepResponse(null);

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doNothing().when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     * 
     * @throws IOException
     * @throws CertificateException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_Exception() throws CertificateException, IOException {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenThrow(new PersistenceException());
        Mockito.doNothing().when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());
        PowerMockito.mockStatic(CertificateUtility.class);
        certificate = (X509Certificate) cryptoService.readCertificate(JUnitConstants.caName, false);
        PowerMockito.mockStatic(JaxbUtil.class);
        PowerMockito.mockStatic(DOMUtil.class);
        Mockito.when(JaxbUtil.getX509CertificateFromDocument((Document) Mockito.any())).thenReturn(certificate);
        Mockito.when(DOMUtil.getDocument((byte[]) Matchers.any())).thenReturn(document);
        Mockito.when(JaxbUtil.getObject(document, ScepResponse.class)).thenReturn(scepResp);
        Mockito.when(scepResp.getTransactionId()).thenReturn("001");

        Mockito.when(CertificateUtility.getIssuerName(certificate)).thenReturn(JUnitConstants.caName);
        X509CRL issuerCRL = null;
        Mockito.when(scepCrlCacheUtil.getCRL(JUnitConstants.caName)).thenReturn(issuerCRL);

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_PkiScepServiceException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(new PkiScepServiceException("PkiScepServiceException Occured")).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_CRLValidationException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(new CRLValidationException("CRLValidationException Occured")).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    /**
     * This method tests processResponse with scepResponseMessage.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_CertificateRevokedException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(CertificateRevokedException.class).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_CertificateException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(CertificateException.class).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_KeyStoreException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(KeyStoreException.class).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testprocessRequest_IOException() {

        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(JUnitConstants.caName);
        Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
        Mockito.when(entityManager.getTransaction()).thenReturn(transaction);
        Mockito.when(entityManager.find((Class<Pkcs7ScepRequestEntity>) Mockito.any(), Mockito.anyString())).thenReturn(pkcs7ScepRequestEntity);
        Mockito.doThrow(IOException.class).when(digitalSignatureValidator).validate((Document) Mockito.any(), Mockito.anySet());

        responseProcessor.processResponse(signedScepResponseMessage);
    }
}
