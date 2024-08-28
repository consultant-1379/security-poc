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
package com.ericsson.oss.itpf.security.pki.ra.scep.builder;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import javax.cache.Cache;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.validator.SignatureValidator;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.ProtocolException;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;

/**
 * This class will test CertResponseBuilder class
 */
@RunWith(MockitoJUnitRunner.class)
public class CertResponseBuilderTest {

    @Mock
    private SystemRecorder systemRecorder;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @InjectMocks
    private CertResponseBuilder certResponseBuilder;

    @Mock
    private PersistenceHandler peristanceHandler;

    @Mock
    private Pkcs7ScepRequestEntity pkcs7ScepRequestEntity;

    @Mock
    private ConfigurationListener configurationListener;

    @Mock
    private KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    private KeyStoreFileReaderFactory keyStoreFileReaderFactoryNew;

    @Mock
    private Logger logger;

    @Mock
    private SignatureValidator signatureValidator;

    @Mock
    private Pkcs7CmsSignedDataBuilder pkcs7CmsSignedDataBuilder;

    @Mock
    private CryptoService cryptoService;

    @Mock
    @NamedCache("SupportedAlgorithmsCache")
    private Cache<String, List<String>> cache;

    private Pkcs7ScepResponseData pkcs7ResponseData;

    @Mock
    private SignerInfoAttributeData signerInfoAttributes;

    @Mock
    private Pkcs7ScepRequestData pkcs7ScepRequestData;

    private KeyStoreInfo keyStoreInfo;
    private String successPkcs = "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggMVMIAGCSqGSIb3DQEHA6CAMIACAQAxggFVMIIBUQIBADA5MDExETAPBgNVBAoMCEVyaWNzc29uMRwwGgYDVQQDDBNMVEVJUFNlY05FY3VzUm9vdENBAgQkbbUQMA0GCSqGSIb3DQEBAQUABIIBAGduY+S9NDgxR5T1RtXjHKGPlFLlPQ21j5LWyyjmNgEauWNKJAOYTpVwFO0ifAE/HmUSb8MP0RRUKLCQlimVgTo3WDkcTqK/gdTeHCfoUv4+VwbnyTS9LWNy6AjKHrR1toYp7FBFOgwC225antK+YTdGD8iXUIiEkQM0vtTO6LccGE2SdRWT90GHoci5ddva4SOuKQ4kPk5dv2+kMC1RNUI0JcV7kVFAPbQ7ttWCSTCoCCcnxxuQ4jIDHEOTeipidAjRNyIagY9/IpuzYi7PE8opqKEUzy4b+qAayiFpuKM4tYrk0Q4Rj1uIrWdyIJ+gtBVOuez5grTV9r/DFAZ0jXswgAYJKoZIhvcNAQcBMBEGBSsOAwIHBAiQPQPjMLa0mKCABIIBeH7JN539cTs/77S1BM830xEu9iiF2b7ECgVcdMjIiyndhdU/ZynJdsTpXfp959CGBB/kir4rMKnuZtx9C9b3YqzmI63U5MFWYnbbVnqSaLGmx0OYokTfhYe58pLE6ECWiAmUhJCdKU+FyBpuBI4Q1lbOpTJUBntgLd9rtLNHBzyzcORnTEHwWsqyxyoh6yus1DREr4lnqAKxJjDhhVYIpDlP4V240yyAiRNz6R3aaUauYJtzP0JQuIe+6quBtfGXbrn8nxfFZN7lhcyq1mjnG+MV/udfecOlw/0pufNT72yqqgMYClMUcdslmtR7wk8FJf8drva4NA7o5mt0i0kRGXRZI+2ehBA+OptmeAj1gwXNl2vlYcPWDqfan3QPw2j8nBett/2dyVgOG6ECkq5XLhpNErjZRWv6+JgCn6+1baYT2ITLyR6U1e+a+MxOYdOzHjWxrPee648ltqs8fCuEERpQlAVGYUpFCR7lBCWxvjvnUmRbipWneHEAAAAAAAAAAAAAAAAAAAAAoIAwggP5MIIC4aADAgECAgQkbbUQMA0GCSqGSIb3DQEBBQUAMDExETAPBgNVBAoMCEVyaWNzc29uMRwwGgYDVQQDDBNMVEVJUFNlY05FY3VzUm9vdENBMB4XDTE0MTEwNTA2MjkyN1oXDTE5MTEwMzEyMjkyMVowLjEsMCoGA1UEAwwjTFRFSVBTZWNORWN1c2F0Y2x2bTEwMjRTY2VwUmFTZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm64AZma+xX1m+VfKbILo5P+D/HL+ctQM4s2Dz7lo/PpVL8bIc5qVtb6GvHBFB/ZFIM0+uFnUuq+aG3Uk4ZXIAQYYDispbznBoCqX7qQTwjpcXn9dvEr3He3vVvOlZUVSgExroLUDgts4MvqekvrxGK5AH6vwrZ6ncdZLqfp55bpDZi5TiYr8NCLFSy2O2akhkZCZ6N8YegeQpr28OPElfLO0T10+9F4UtNS8yqismmwMZbc4MT8RoxwCQXSDJH+t0Q9JNgoPBKkZbCb3HVbVEM0mCRy/zDPoJfFrCIehqJlsBQaAyCY541cUvnpPSfOy9vqjpj0vjP13S+BwlE6jTAgMBAAGjggEaMIIBFjAdBgNVHQ4EFgQU+JIv/d5j3ms9oAjo5igxj0C0Vp4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSS544k8jDdLz91h+J5ZyyERYoPODCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY2RwMS5jZHBzLmF0aHRlbS5lZWkuZXJpY3Nzb24uc2U6MjM3Ny9pbnRlcm5hbC9MVEVJUFNlY05FY3VzUm9vdENBLmNybDBToFGgT4ZNaHR0cDovL2NkcDIuY2Rwcy5hdGh0ZW0uZWVpLmVyaWNzc29uLnNlOjIzNzcvaW50ZXJuYWwvTFRFSVBTZWNORWN1c1Jvb3RDQS5jcmwwDgYDVR0PAQH/BAQDAgOoMA0GCSqGSIb3DQEBBQUAA4IBAQA7jRzkFMlkv19BeqBuNYZ830pqRX5P5aNqhytQbpwrThke2PfHVyS10j/vsuawj3Gm44pB9WYx7QmCFj2oGVKjRbYzotTKmwNqkABhIV+Hzx23AY4aSWRKgYoME4Pd2q4zTb++qN99rsLdi7/MEfnanMb6HxLIRGCZWi0rqk6X/JHqrEXaoHG6T6LeFKyMFS4DVEpx6FBCe7UCDRFykbOcAfgGjzalfxiY/DhdfBWKym3sucvp9Xcn3a0YPgjNGyf0kQJcSMUaYVGSxsHwTARyoRckgIc5zZw/VEo1XClBkK0tlRwsX0xc0IQk6Pg+Wnr8gfi9q3F1Vikwaj4EXoGBAAAxggIbMIICFwIBATA5MDExETAPBgNVBAoMCEVyaWNzc29uMRwwGgYDVQQDDBNMVEVJUFNlY05FY3VzUm9vdENBAgQkbbUQMAkGBSsOAwIaBQCggbgwEgYKYIZIAYb4RQEJAjEEEwIxOTAXBgpghkgBhvhFAQkHMQkTBzIuMy40LjUwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTUwNzA4MDcwNzE3WjAgBgpghkgBhvhFAQkFMRIEEKth9Dl4xOJWfuIIiz1iKRAwLwYJKoZIhvcNAQkEMSIEID26ytTVbUQTRaKYkcDXv+WU4OQQb5q4mF1IESV76i/wMA0GCSqGSIb3DQEBAQUABIIBAB+4DvqaJIvT7UPps1lokP4DdlEH6tcJOdgwmPh6KL6+8R3WHOZ8ODu563g2yCR3XiPHXB6i/8uOGgVCk+YE+Q7eK9dEONgfa66d58ygHgrB7VCvyUqNFujZ+U3nL0sbKOrSxsS9EaQvfyQV4vkBrpRLxLMhlq1t+1tcp9ICIfTi9O39tToO/LKw6J0Pm/2sIZBSKvZhJPiOD6Muyq7sBUWH1D1DiHWW8iDqReFjg+lVFatV8voBq563wW/daloABvhqlw+eQwH2QzCyoFWS6xLMKfZ4pD+sDL97FvyjRgYh6Lja9dZFv1f21ANHtQPuSrQcpwelOU86m38984qZ3ocAAAAAAAA=";

    private X509Certificate certificate = null;
    private PrivateKey privateKey;
    String expectedTransactionID = "2.3.4.5";

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @Before
    public void setUp() {
        pkcs7ResponseData = new Pkcs7ScepResponseData();
        pkcs7ScepRequestData = null;
        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
            keyStore.load(CertResponseBuilderTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());
            keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, JUnitConstants.password, JUnitConstants.caName);
            privateKey = (PrivateKey) keyStore.getKey(keyStoreInfo.getAliasName(), keyStoreInfo.getPassword().toCharArray());
            certificate = (X509Certificate) keyStore.getCertificate(JUnitConstants.caName);
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e) {
            Assert.fail(e.getMessage());
        }

    }

    private void setPKCS7RequestData(final String msg) {
        pkcs7ScepRequestData = Pkcs7ScepRequestSetUpData.getPkcs7ScepRequest(Base64.decode(msg));
    }

    /**
     * This method will take input pkcs7ScepRequestData ,caName ,pkcs7ResponseData and creates response in bytes and asserts that status of response as PENDING.
     */
    @Test
    public void testCreatePendingCertResponse() {
        try {
            setPKCS7RequestData(successPkcs);
            Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
            Mockito.when(signerInfoAttributes.getTransactionId()).thenReturn(pkcs7ScepRequestData.getTransactionId());
            Mockito.when(signerInfoAttributes.getRecipientNonce()).thenReturn(pkcs7ScepRequestData.getSenderNonce());
            Mockito.when(signerInfoAttributes.getDigestAlgorithm()).thenReturn(pkcs7ScepRequestData.getContentDigestAlgOid());
            Mockito.when(signerInfoAttributes.getStatus()).thenReturn(ResponseStatus.PENDING);
            Mockito.when(cryptoService.readPrivateKey(JUnitConstants.caName)).thenReturn(privateKey);
            certResponseBuilder.populateResponseData(pkcs7ScepRequestData, JUnitConstants.caName, pkcs7ResponseData);

            final byte[] pendingResponse = certResponseBuilder.buildPendingCertResponse();
            Mockito.verify(logger).debug("End of createPendingCertResponse method in CertResponseBuilder class");

            final String status = getStatus(pendingResponse);
            final String actualTransactionID = getTransactionID(pendingResponse);
            final int pendingStatus = Integer.valueOf(status);
            assertEquals(pendingStatus, ResponseStatus.PENDING.getStatus());
            assertEquals(expectedTransactionID, actualTransactionID);
        } catch (ProtocolException e) {
            Assert.fail("Fail to build response");
        }
    }

    /**
     * This method will take input pkcs7ScepRequestData ,caName ,pkcs7ResponseData and creates response in bytes and asserts that status of response as FAILURE.
     *
     * @throws ProtocolException
     * @throws CertificateEncodingException
     */

    @Test(expected = NullPointerException.class)
    public void testCreatePendingCertFailureScenario() throws ProtocolException, CertificateEncodingException {
        try {
            setPKCS7RequestData(successPkcs);
            Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
            Mockito.when(signerInfoAttributes.getTransactionId()).thenReturn(pkcs7ScepRequestData.getTransactionId());
            Mockito.when(signerInfoAttributes.getRecipientNonce()).thenReturn(pkcs7ScepRequestData.getSenderNonce());
            Mockito.when(signerInfoAttributes.getStatus()).thenReturn(ResponseStatus.FAILURE);
            keyStoreInfo.setFilePath(null);
            keyStoreInfo.setKeyStoreType(null);
            keyStoreInfo.setPassword(null);
            certResponseBuilder.populateResponseData(null, JUnitConstants.caName, pkcs7ResponseData);
        } catch (ProtocolException e) {
            Assert.fail("Fail to build response");
        }
    }

    /**
     * This method will take input pkcs7ScepRequestData ,caName ,pkcs7ResponseData and creates response in bytes and asserts that status of response with FailureInfo as BadAlg
     */
    @Test
    public void testCreateFailureCertResponse() {
        try {
            setPKCS7RequestData(successPkcs);
            Mockito.when(cryptoService.readCertificate(JUnitConstants.caName, false)).thenReturn(certificate);
            Mockito.when(signerInfoAttributes.getTransactionId()).thenReturn(pkcs7ScepRequestData.getTransactionId());
            Mockito.when(signerInfoAttributes.getRecipientNonce()).thenReturn(pkcs7ScepRequestData.getSenderNonce());
            Mockito.when(signerInfoAttributes.getDigestAlgorithm()).thenReturn(pkcs7ScepRequestData.getContentDigestAlgOid());
            Mockito.when(signerInfoAttributes.getStatus()).thenReturn(ResponseStatus.FAILURE);
            Mockito.when(cryptoService.readPrivateKey(JUnitConstants.caName)).thenReturn(privateKey);
            certResponseBuilder.populateResponseData(pkcs7ScepRequestData, JUnitConstants.caName, pkcs7ResponseData);
            final byte[] pkiScepResponse = certResponseBuilder.buildFailureCertResponse(FailureInfo.BADALG);
            Mockito.verify(logger).debug("End of createFailureCertResponse method in CertResponseBuilder class");
            final String status = getStatus(pkiScepResponse);
            final String actualTransactionID = getTransactionID(pkiScepResponse);
            final int failureStatus = Integer.valueOf(status);
            assertEquals(failureStatus, ResponseStatus.FAILURE.getStatus());
            assertEquals(expectedTransactionID, actualTransactionID);
        } catch (ProtocolException e) {
            Assert.fail("Fail to build response");
        }

    }

    /**
     * This method will take input pkcs7ScepRequestData ,caName ,pkcs7ResponseData and creates response in bytes and asserts that status of response as SUCCESS
     */

    @Test
    public void testCreateSuccessCertResponse() {
        try {
            setPKCS7RequestData(successPkcs);
            Mockito.when(signerInfoAttributes.getTransactionId()).thenReturn(pkcs7ScepRequestData.getTransactionId());
            Mockito.when(signerInfoAttributes.getRecipientNonce()).thenReturn(pkcs7ScepRequestData.getSenderNonce());
            Mockito.when(signerInfoAttributes.getDigestAlgorithm()).thenReturn(pkcs7ScepRequestData.getContentDigestAlgOid());
            Mockito.when(signerInfoAttributes.getStatus()).thenReturn(ResponseStatus.SUCCESS);
            Mockito.when(cryptoService.readPrivateKey(JUnitConstants.caName)).thenReturn(privateKey);
            certResponseBuilder.populateResponseData(pkcs7ScepRequestData, JUnitConstants.caName, pkcs7ResponseData);
            pkcs7ResponseData.setSignerCertificate(pkcs7ScepRequestData.getSignerCertificate());
            final java.security.cert.Certificate cert = getCertificate();
            final byte[] pkiScepResponse = certResponseBuilder.buildSuccessCertResponse(cert.getEncoded());
            Mockito.verify(logger).debug("End of createSuccessCertResponse method in CertResponseBuilder class");
            final String status = getStatus(pkiScepResponse);
            final String actualTransactionID = getTransactionID(pkiScepResponse);
            final int successStatus = Integer.valueOf(status);
            assertEquals(successStatus, ResponseStatus.SUCCESS.getStatus());
            assertEquals(expectedTransactionID, actualTransactionID);
        } catch (ProtocolException | CertificateEncodingException e) {
            // Assert.fail("Fail to build response");
        }

    }

    /**
     * testCreateSucCertRespFailScenario will test the certResponse builder when a null input is sent
     */
    @Test(expected = ProtocolException.class)
    public void testCreateSucCertRespFailScenario() {
        certResponseBuilder.buildSuccessCertResponse(null);
    }

    public Certificate getCertificate() {
        java.security.cert.Certificate cert = null;

        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
            keyStore.load(CertResponseBuilderTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());
            cert = keyStore.getCertificate(JUnitConstants.caName);

        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
        return cert;
    }

    /**
     * getStatus method will fetch the Status from a given pkiScepResponse
     * 
     * @param pkiScepResponse
     * @return status of the pkiScepResponse
     */
    private String getStatus(final byte[] pkiScepResponse) {
        SignerInformation signerInformation = extractSignerInformation(pkiScepResponse);
        return getStatus(signerInformation);

    }

    /**
     * getTransactionID method will fetch the TransactionID from a given pkiScepResponse
     * 
     * @param pkiScepResponse
     * @return TransactionID of the pkiScepResponse
     */
    private String getTransactionID(final byte[] pkiScepResponse) {
        SignerInformation signerInformation = extractSignerInformation(pkiScepResponse);
        return getTransactionID(signerInformation);
    }

    /**
     * extractSignerInformation method will extract SignerInformation from the given pkiScepResponse
     * 
     * @param pkiScepResponse
     * @return SignerInformation of the pkiScepResponse
     */
    private SignerInformation extractSignerInformation(final byte[] pkiScepResponse) {
        CMSSignedData cmsSignedData = null;
        try {
            cmsSignedData = new CMSSignedData(pkiScepResponse);
        } catch (final CMSException e) {
            Assert.fail(e.getMessage());
        }
        final SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
        final Collection<?> signers = signerInformationStore.getSigners();
        final Iterator<?> it = signers.iterator();
        SignerInformation signerInformation = null;
        if (it.hasNext()) {
            signerInformation = (SignerInformation) it.next();
        }
        return signerInformation;
    }

    /**
     * getStatus will fetch the Status for a given SignerInformation
     * 
     * @param signerInformation
     * @return status of the SignerInformation
     */
    @SuppressWarnings("unchecked")
    private String getStatus(final SignerInformation signerInformation) {
        DERPrintableString attributeString = null;
        final AttributeTable attributeTable = signerInformation.getSignedAttributes();
        final Hashtable<ASN1ObjectIdentifier, Attribute> hashTable = attributeTable.toHashtable();
        for (final ASN1ObjectIdentifier asn1AtrributeOID : hashTable.keySet()) {
            final Attribute attribute = attributeTable.get(asn1AtrributeOID);
            if (attribute != null) {
                final ASN1Set values = attribute.getAttrValues();

                final Enumeration<?> enumeration = values.getObjects();
                if (asn1AtrributeOID.toString().equals(Constants.STATUS_OID)) {
                    if (enumeration.hasMoreElements()) {
                        attributeString = (DERPrintableString) enumeration.nextElement();

                    }
                }
            }
        }
        return attributeString.getString();
    }

    /**
     * getTransactionID will fetch the TransactionID for a given SignerInformation
     * 
     * @param signerInformation
     * @return TransactionID of the SignerInformation
     */
    @SuppressWarnings("unchecked")
    private String getTransactionID(final SignerInformation signerInformation) {
        DERPrintableString attributeString = null;
        final AttributeTable attributeTable = signerInformation.getSignedAttributes();
        final Hashtable<ASN1ObjectIdentifier, Attribute> hashTable = attributeTable.toHashtable();
        for (final ASN1ObjectIdentifier asn1AtrributeOID : hashTable.keySet()) {
            final Attribute attribute = attributeTable.get(asn1AtrributeOID);
            if (attribute != null) {
                final ASN1Set values = attribute.getAttrValues();

                final Enumeration<?> enumeration = values.getObjects();
                if (asn1AtrributeOID.toString().equals(Constants.TRANSACTION_ID)) {
                    if (enumeration.hasMoreElements()) {
                        attributeString = (DERPrintableString) enumeration.nextElement();

                    }
                }
            }
        }
        return attributeString.getString();
    }

}
