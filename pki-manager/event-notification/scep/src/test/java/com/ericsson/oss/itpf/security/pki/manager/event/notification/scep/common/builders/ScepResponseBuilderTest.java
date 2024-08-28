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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.common.builders;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;

@RunWith(MockitoJUnitRunner.class)
/**
 * Test class for ScepResponseBuilderTest
 * 
 */
public class ScepResponseBuilderTest {

    @Mock
    private Logger logger;
    @InjectMocks
    private ScepResponseBuilder scepResponseBuilder;

    @Mock
    private SystemRecorder systemRecorder;

    private static String transactionId;

    private static int status;

    private static String failureInfo;
    @Mock
    private static X509Certificate certificate;

    @Mock
    private CredentialsManager credentialManager;

    private PrivateKey privateKey = null;
    private X509Certificate signerCertificate = null;

    private final String keyStoreType = "PKCS12";
    private final String filePath = "/LTEIPSecNEcus_Sceprakeystore_1.p12";
    private final String password = "C4bCzXyT";
    private final String keyStoreAlias = "lteipsecnecus";

    /**
     * 
     * Prepares initial set up required to run the test case.
     * 
     * @throws UnrecoverableKeyException
     */
    @Before
    public void setUpBeforeClass() throws UnrecoverableKeyException {
        transactionId = "12314";
        status = 1;
        failureInfo = "FAILURE";
        setSignerCertificateAndPrivateKey();
    }

    /**
     * Method to test scepResponseMessage.
     * 
     * @throws CertificateEncodingException
     */
    @Test
    public void buildScepResponseMessageTest() throws CertificateEncodingException {
        Mockito.when(credentialManager.getSignerCertificate()).thenReturn(signerCertificate);
        Mockito.when(credentialManager.getSignerPrivateKey()).thenReturn(privateKey);
        scepResponseBuilder.buildScepResponse(transactionId, status, failureInfo, certificate);
    }

    /**
     * Method to test buildScepResponse DigitalSigningFailedException.
     * 
     * @throws CertificateEncodingException
     */
    @Test(expected = DigitalSigningFailedException.class)
    public void testBuildScepResponse_DigitalSigningFailedException() throws CertificateEncodingException {
        Mockito.when(credentialManager.getSignerCertificate()).thenReturn(signerCertificate);
        Mockito.when(credentialManager.getSignerPrivateKey()).thenThrow(new DigitalSigningFailedException("Fail to sign SCEP response message"));
        scepResponseBuilder.buildScepResponse(transactionId, status, failureInfo, certificate);
    }

    private void setSignerCertificateAndPrivateKey() throws UnrecoverableKeyException {
        try {
            final KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(ScepResponseBuilderTest.class.getResourceAsStream(filePath), password.toCharArray());
            Certificate cert = keyStore.getCertificate(keyStoreAlias);
            signerCertificate = (X509Certificate) cert;
            privateKey = (PrivateKey) keyStore.getKey(keyStoreAlias, password.toCharArray());
        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }
}
