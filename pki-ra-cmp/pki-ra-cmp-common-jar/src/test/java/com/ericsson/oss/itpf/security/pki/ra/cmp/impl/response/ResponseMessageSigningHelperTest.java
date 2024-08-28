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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.cache.Cache;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.IPResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.AbstractMain;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.RequestType;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.response.generator.ResponseType;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.KeyStoreUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.UnsupportedAlgorithmException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.ResponseSigner;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.SupportedAlgorithmsCacheWrapper;

@RunWith(MockitoJUnitRunner.class)
public class ResponseMessageSigningHelperTest {
    private static final String ISSUERNAME = "TestCA";
    @InjectMocks
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Mock
    InitialConfiguration configurationData;

    @Mock
    ConfigurationParamsListener configurationListener;

    @Mock
    ResponseSigner messageSigner;

    @Mock
    Cache<String, List<String>> algorithmDataCache;

    @Mock
    SupportedAlgorithmsCacheWrapper supportedAlgorithmsCacheWrapper;

    @Mock
    Logger logger;

    private static RequestMessage requestmessage;
    private static ResponseMessage responseMessage;

    private static X509Certificate x509Certificate;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        final Parameters responseParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiIPWithWaitResponseMessage = ResponseGeneratorFactory.getResponseGenerator(ResponseType.IP_WITH_WAIT_RESPONSE).generate(pkiRequestMessage, responseParameters);

        requestmessage = new RequestMessage(pkiRequestMessage.getEncoded());
        responseMessage = new IPResponseMessage(pkiIPWithWaitResponseMessage.getEncoded());
        x509Certificate = requestmessage.getUserCertificate();
    }

    @Test
    public void testSignMessage() throws Exception {
        setUpTestData();
        final List<String> listOfAlgOid = new ArrayList<>();
        listOfAlgOid.add("1.2.840.113549.1.1.5");
        Mockito.when((configurationListener).getAlgorithmForIAKSigning()).thenReturn("1.2.840.113549.1.1.5");
        Mockito.when(supportedAlgorithmsCacheWrapper.get(Mockito.anyString())).thenReturn(listOfAlgOid);
        responseMessageSigningHelper.signMessage(ISSUERNAME, responseMessage);

        Mockito.verify(configurationData).getSignerCertificate(ISSUERNAME);
        Mockito.verify(configurationData).getKeyPair(ISSUERNAME);

    }

    @Test
    public void testSignMessageForIAK() throws Exception {
        setUpTestData();
        final List<String> listOfAlgOid = new ArrayList<>();
        listOfAlgOid.add("1.2.840.113549.1.1.5");
        Mockito.when((configurationListener).getAlgorithmForIAKSigning()).thenReturn("1.2.840.113549.1.1.5");
        Mockito.when(supportedAlgorithmsCacheWrapper.get(Mockito.anyString())).thenReturn(listOfAlgOid);

        responseMessageSigningHelper.signMessage(ISSUERNAME, responseMessage);

        Mockito.verify(configurationData).getSignerCertificate(ISSUERNAME);
        Mockito.verify(configurationData).getKeyPair(ISSUERNAME);

    }

    @Test
    public void testGetSenderFromSignerCert() throws Exception {
        Mockito.when(configurationData.getSignerCertificate(ISSUERNAME)).thenReturn(x509Certificate);

        responseMessageSigningHelper.getSenderFromSignerCert(ISSUERNAME);

        Mockito.verify(configurationData).getSignerCertificate(ISSUERNAME);

    }

    @Test(expected = InvalidInitialConfigurationException.class)
    public void testInitialConfigurationException() throws Exception {
        responseMessageSigningHelper.signMessage(ISSUERNAME, responseMessage);

    }

    @Test
    public void testBuildCMPExtraCertsForResponseFromManager() throws Exception {

        Mockito.when(configurationData.getSignerCertificate(ISSUERNAME)).thenReturn(x509Certificate);

        responseMessageSigningHelper.buildCMPExtraCertsForResponseFromManager(ISSUERNAME, responseMessage);

        Mockito.verify(configurationData).getRACertificateChain(ISSUERNAME);

    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void testSignMessageUnsupportedAlgorithmException() throws Exception {
        setUpTestData();

        Mockito.when(configurationData.getKeyPair(ISSUERNAME)).thenThrow(new UnsupportedAlgorithmException("Exception"));

        responseMessageSigningHelper.signMessage(ISSUERNAME, responseMessage);

        Mockito.verify(configurationData).getSignerCertificate(ISSUERNAME);
        Mockito.verify(configurationData).getKeyPair(ISSUERNAME);

    }

    private void setUpTestData() throws NoSuchAlgorithmException {
        final Parameters parameters = setParameters();
        final KeyPair keyPair = KeyStoreUtility.generateKeyPair(parameters.getKeyAlgorithm(), parameters.getKeySize());
        setMocks(keyPair);
    }

    private void setMocks(final KeyPair keyPair) {
        Mockito.when(configurationData.getSignerCertificate(ISSUERNAME)).thenReturn(x509Certificate);
        Mockito.when(configurationData.getKeyPair(ISSUERNAME)).thenReturn(keyPair);
    }

    private Parameters setParameters() {
        final Parameters parameters = new Parameters();
        parameters.setKeyAlgorithm("RSA");
        parameters.setKeySize(1024);
        return parameters;
    }

}
