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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.test.request.WorkingMode;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidMessageException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.TrustStoreUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils.BaseDigitalSignatureValidatorTestUtil;

@RunWith(PowerMockRunner.class)
public class DigitalSignatureForNegativeScenarioTest {
    @InjectMocks
    DigitalSignatureValidator digitalSignatureValidator;

    @Mock
    PKIXCertificatePathBuilder pKIXCertificatePathBuilder;

    @Mock
    Logger logger;

    @Mock
    TrustStoreUtil trustStore;

    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKIReqForNoSuchProtAlgoException;
    private static RequestMessage pKIInvalidSignatureRequestMsg;
    private static RequestMessage pKIInvalidProtectionBytesReqMsg;

    private static Set<X509Certificate> vendorCertificateSet = null;
    private static Set<X509Certificate> certificateChain = null;
    private static X509Certificate userCertificate = null;

    @BeforeClass
    public static void prepareTestData() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);

        final Parameters requestParameters1 = AbstractMain.configureParameters(null);
        requestParameters1.setValidProtectionBytes(false);

        final Parameters requestParameters2 = AbstractMain.configureParameters(null);
        requestParameters2.setMode(WorkingMode.WRONG_DIGITAL_SIGN_IR);

        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        requestParameters.setValidProtectionAlgo(false);
        final PKIMessage pkiReqForNoSuchProtAlgoException = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        final PKIMessage pkiInvalidRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters2, null);
        final PKIMessage pkiInvalidProtectionBytesReqMsg = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters1, null);

        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        pKIReqForNoSuchProtAlgoException = new RequestMessage(pkiReqForNoSuchProtAlgoException.getEncoded());
        pKIInvalidSignatureRequestMsg = new RequestMessage(pkiInvalidRequestMessage.getEncoded());
        pKIInvalidProtectionBytesReqMsg = new RequestMessage(pkiInvalidProtectionBytesReqMsg.getEncoded());

        vendorCertificateSet = BaseDigitalSignatureValidatorTestUtil.getVendorCerts();
        certificateChain = pKIRequestMessage.getCertChainSet();
        userCertificate = pKIRequestMessage.getUserCertificate();

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testDigitalSignatureValidationExceptionForValidate() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIInvalidSignatureRequestMsg)).thenReturn(vendorCertificateSet);

        digitalSignatureValidator.validate(pKIInvalidSignatureRequestMsg);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testDigitalSignatureValidationException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIInvalidProtectionBytesReqMsg)).thenReturn(vendorCertificateSet);

        digitalSignatureValidator.validate(pKIInvalidProtectionBytesReqMsg);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForInvalidAlgorithmParameterException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenReturn(vendorCertificateSet);
        Mockito.when(pKIXCertificatePathBuilder.build(userCertificate, certificateChain, vendorCertificateSet)).thenThrow(new InvalidAlgorithmParameterException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForInvalidSignature() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenReturn(vendorCertificateSet);
        Mockito.when(pKIXCertificatePathBuilder.build(userCertificate, certificateChain, vendorCertificateSet)).thenThrow(new InvalidAlgorithmParameterException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForNoSuchProtAlgoException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIReqForNoSuchProtAlgoException)).thenReturn(vendorCertificateSet);

        digitalSignatureValidator.validate(pKIReqForNoSuchProtAlgoException);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForCertPathBuilderException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenReturn(vendorCertificateSet);
        Mockito.when(pKIXCertificatePathBuilder.build(userCertificate, certificateChain, vendorCertificateSet)).thenThrow(new CertPathBuilderException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForNoSuchAlgorithmException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenReturn(vendorCertificateSet);
        Mockito.when(pKIXCertificatePathBuilder.build(userCertificate, certificateChain, vendorCertificateSet)).thenThrow(new NoSuchAlgorithmException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForCertificateParseException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenThrow(new CertificateParseException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForInvalidCertificateVersionException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenThrow(new InvalidCertificateVersionException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForInvalidInitialConfigurationException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenThrow(new InvalidInitialConfigurationException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForMessageParsingException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenThrow(new MessageParsingException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForInvalidMessageException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenThrow(new InvalidMessageException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }

    @Test(expected = DigitalSignatureValidationException.class)
    public void testForIOException() throws Exception {

        Mockito.when(trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage)).thenThrow(new IOException());

        digitalSignatureValidator.validate(pKIRequestMessage);

    }
}
