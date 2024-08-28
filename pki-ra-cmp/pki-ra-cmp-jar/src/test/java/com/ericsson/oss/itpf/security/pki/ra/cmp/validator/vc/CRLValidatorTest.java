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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.exception.*;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateChainCRLValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateRevokeValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidMessageException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.TrustStoreUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.BaseDigitalSignatureValidatorTestUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.CRLStore;

@RunWith(MockitoJUnitRunner.class)
public class CRLValidatorTest {

    @InjectMocks
    CRLValidator crlValidator;

    @Mock
    TrustStoreUtil trustStore;

    @Mock
    PKIXCertificatePathBuilder pKIXCertificatePathBuilder;

    @Mock
    CertificateChainCRLValidator issuerCRLValidator;

    @Mock
    CertificateRevokeValidator isCertificateRevokedValidator;

    @Mock
    InitialConfiguration configurationData;

    @Mock
    PKIXCertPathBuilderResult result;

    @Mock
    Set<X509Certificate> certificateChain;

    @Mock
    Logger logger;

    @Mock
    CRLStore crlStore;

    private static RequestMessage pKIRequestMessage;
    private static X509Certificate userCertificate = null;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        userCertificate = pKIRequestMessage.getUserCertificate();
    }

    @Test
    public void testValidate() throws Exception {

        final Set<X509Certificate> certificateChain = pKIRequestMessage.getCertChainSet();
        final Set<X509Certificate> trustedCerts = trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage);

        final PKIXCertPathBuilderResult builderResult = pKIXCertificatePathBuilder.build(userCertificate, certificateChain, trustedCerts);
        final Set<X509Certificate> vendorCertificateSet = new HashSet<X509Certificate>();

        vendorCertificateSet.add(userCertificate);
        vendorCertificateSet.addAll(BaseDigitalSignatureValidatorTestUtil.getVendorCerts());

        Mockito.when(pKIXCertificatePathBuilder.getCertificateChain(builderResult)).thenReturn(vendorCertificateSet);
        crlValidator.validate(pKIRequestMessage);

        Mockito.verify(logger).info("CRL validation started for request Message : {} ", pKIRequestMessage.getRequestMessage());

    }

    @Test
    public void testValidateKeyStoreException() throws Exception {
        final Set<X509Certificate> vendorCertificates = configurationData.getVendorCertificateSet();
        final Set<X509Certificate> caCertificates = configurationData.getCaCertificateSet();

        Mockito.doThrow(new KeyStoreException()).when(issuerCRLValidator).validateIssuerCRL(null, null, vendorCertificates);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testIOException() throws Exception {
        Mockito.doThrow(new IOException()).when(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testInvalidAlgorithmParameterException() throws Exception {
        final Set<X509Certificate> vendorCertificates = configurationData.getVendorCertificateSet();
        final Set<X509Certificate> caCertificates = configurationData.getCaCertificateSet();
        Mockito.doThrow(new InvalidAlgorithmParameterException()).when(pKIXCertificatePathBuilder).build(userCertificate, vendorCertificates, caCertificates);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testNoSuchAlgorithmException() throws Exception {
        final Set<X509Certificate> vendorCertificates = configurationData.getVendorCertificateSet();
        final Set<X509Certificate> caCertificates = configurationData.getCaCertificateSet();
        Mockito.doThrow(new NoSuchAlgorithmException()).when(pKIXCertificatePathBuilder).build(userCertificate, vendorCertificates, caCertificates);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testCertPathBuilderException() throws Exception {
        final Set<X509Certificate> vendorCertificates = configurationData.getVendorCertificateSet();
        final Set<X509Certificate> caCertificates = configurationData.getCaCertificateSet();
        Mockito.doThrow(new CertPathBuilderException()).when(pKIXCertificatePathBuilder).build(userCertificate, vendorCertificates, caCertificates);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testCertificateException() throws Exception {
        Mockito.doThrow(new CertificateException()).when(pKIXCertificatePathBuilder).getCertificateChain((PKIXCertPathBuilderResult) Matchers.anyObject());
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testInvalidInitialConfigurationException() throws Exception {
        Mockito.doThrow(new InvalidInitialConfigurationException()).when(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testInvalidMessageException() throws Exception {
        Mockito.doThrow(new InvalidMessageException()).when(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testMessageParsingException() throws Exception {
        Mockito.doThrow(new MessageParsingException()).when(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testCertificateParseException() throws Exception {
        Mockito.doThrow(new CertificateParseException()).when(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testInvalidCertificateVersionException() throws Exception {
        Mockito.doThrow(new InvalidCertificateVersionException()).when(trustStore).getTrustedCertsBasedOnRequestType(pKIRequestMessage);
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testCertificateIsNullException() throws Exception {
        Mockito.doThrow(new CertificateIsNullException()).when(pKIXCertificatePathBuilder).getCertificateChain((PKIXCertPathBuilderResult) Matchers.anyObject());
        crlValidator.validate(pKIRequestMessage);
    }

    @Test(expected = CRLValidationException.class)
    public void testCertificateFactoryNotFoundException() throws Exception {
        Mockito.doThrow(new CertificateFactoryNotFoundException("Error")).when(pKIXCertificatePathBuilder).getCertificateChain((PKIXCertPathBuilderResult) Matchers.anyObject());
        crlValidator.validate(pKIRequestMessage);
    }
}
