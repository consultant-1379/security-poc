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

import javax.persistence.PersistenceException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.Pkcs7ScepRequestSetUpData;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.event.sender.SignedScepRequestMessageSender;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;

/**
 * This class contains the test for PkcsRequestProcessor
 */
@RunWith(MockitoJUnitRunner.class)
public class PkcsRequestProcessorTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private String successPkcs = "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";

    private Pkcs7ScepRequestData pkcs7ScepRequestData;
    private byte[] message = null;

    @InjectMocks
    private PkcsRequestProcessor pkcsRequestProcessor;
    @Mock
    private PkiOperationReqProcessor pkiOperReqProcessor;
    @Mock
    private Logger logger;
    @Mock
    private Pkcs7ScepRequestEntity requestPkcs7ScepRequestEntity;
    @Mock
    private PersistenceHandler peristanceHandler;
    @Mock
    private SignedScepRequestMessageSender requestMessageSender;
    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    ConfigurationListener configurationListener;
    @Mock
    CryptoService cryptoService;

    private PrivateKey privateKey = null;
    private X509Certificate signerCertificate = null;
    private String keyStoreAlias = JUnitConstants.caName;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    @Before
    public void setUp() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        message = successPkcs.getBytes();
        pkcs7ScepRequestData = new Pkcs7ScepRequestData();
        if (StringUtility.isBase64(new String(message))) {
            message = Base64.decode(message);
        }
        pkcs7ScepRequestData = Pkcs7ScepRequestSetUpData.getPkcs7ScepRequest(message);
        setSignerCertificateAndPrivateKey();
        mockSignerCertificateAndKey();

    }

    /**
     * This method tests processRequest
     */
    @Test
    public void testProcessRequest() {
        final int status = 1;
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        Mockito.when(peristanceHandler.getPkcs7ScepRequestEntity(transactionId)).thenReturn(requestPkcs7ScepRequestEntity);
        Mockito.when(requestPkcs7ScepRequestEntity.getSubjectname()).thenReturn(pkcs7ScepRequestData.getSubjectName());
        Mockito.when(requestPkcs7ScepRequestEntity.getIssuername()).thenReturn(pkcs7ScepRequestData.getIssuerName());
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
        Mockito.verify(logger).debug("End of processRequest method of PkcsRequestProcessor");
    }

    /**
     * The method testProcessRequest_Fail will test when a invalid PKCS request message is provided and check for a bad request exception
     */
    @Test(expected = BadRequestException.class)
    public void testProcessRequest_Fail() {
        final int status = 1;
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        Mockito.when(peristanceHandler.getPkcs7ScepRequestEntity(transactionId)).thenReturn(requestPkcs7ScepRequestEntity);
        Mockito.when(requestPkcs7ScepRequestEntity.getSubjectname()).thenReturn("Subject");
        Mockito.when(requestPkcs7ScepRequestEntity.getIssuername()).thenReturn(pkcs7ScepRequestData.getIssuerName());
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
    }

    /**
     * The method testProcessRequestNull will test when a PKCS request message is null
     */
    @Test
    public void testProcessRequestNull() {
        final int status = 1;
        Mockito.when(requestPkcs7ScepRequestEntity.getSubjectname()).thenReturn("Subject");
        Mockito.when(requestPkcs7ScepRequestEntity.getIssuername()).thenReturn(pkcs7ScepRequestData.getIssuerName());
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
    }

    @Test(expected = PkiScepServiceException.class)
    public void testProcessRequest_BadRequestException() {

        final int status = 1;
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        Mockito.when(peristanceHandler.getPkcs7ScepRequestEntity(transactionId)).thenReturn(requestPkcs7ScepRequestEntity);
        Mockito.when(requestPkcs7ScepRequestEntity.getSubjectname()).thenReturn(pkcs7ScepRequestData.getSubjectName());
        Mockito.when(requestPkcs7ScepRequestEntity.getIssuername()).thenReturn(pkcs7ScepRequestData.getIssuerName());
        Mockito.when(cryptoService.readCertificate(Matchers.anyString(), Matchers.anyBoolean())).thenThrow(new BadRequestException("Invalid Alias name"));
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
        Mockito.verify(logger).info("End of processRequest method of PkcsRequestProcessor");
    }

    @Test(expected = PkiScepServiceException.class)
    public void testProcessRequest_DigitalSigningFailedException() {

        final int status = 1;
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        Mockito.when(peristanceHandler.getPkcs7ScepRequestEntity(transactionId)).thenReturn(requestPkcs7ScepRequestEntity);
        Mockito.when(requestPkcs7ScepRequestEntity.getSubjectname()).thenReturn(pkcs7ScepRequestData.getSubjectName());
        Mockito.when(requestPkcs7ScepRequestEntity.getIssuername()).thenReturn(pkcs7ScepRequestData.getIssuerName());
        Mockito.when(cryptoService.readCertificate(Matchers.anyString(), Matchers.anyBoolean())).thenThrow(new DigitalSigningFailedException("Invalid signature"));
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
        Mockito.verify(logger).info("End of processRequest method of PkcsRequestProcessor");
    }

    @Test(expected = PkiScepServiceException.class)
    public void testProcessRequest_PkiScepServiceException() {

        final int status = 1;
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        Mockito.when(peristanceHandler.getPkcs7ScepRequestEntity(transactionId)).thenReturn(requestPkcs7ScepRequestEntity);
        Mockito.when(requestPkcs7ScepRequestEntity.getSubjectname()).thenReturn(pkcs7ScepRequestData.getSubjectName());
        Mockito.when(requestPkcs7ScepRequestEntity.getIssuername()).thenReturn(pkcs7ScepRequestData.getIssuerName());
        Mockito.when(cryptoService.readCertificate(Matchers.anyString(), Matchers.anyBoolean())).thenThrow(new PkiScepServiceException("Internal error"));
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
        Mockito.verify(logger).info("End of processRequest method of PkcsRequestProcessor");
    }

    @Test(expected = PkiScepServiceException.class)
    public void testProcessRequest_PersistenceException() {

        final int status = 1;
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        Mockito.when(peristanceHandler.getPkcs7ScepRequestEntity(transactionId)).thenThrow(new PersistenceException());
        pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
        Mockito.verify(logger).info("End of processRequest method of PkcsRequestProcessor");
    }

    private void setSignerCertificateAndPrivateKey() throws UnrecoverableKeyException {
        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
            keyStore.load(PkcsRequestProcessorTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());
            Certificate cert = keyStore.getCertificate(keyStoreAlias);
            signerCertificate = (X509Certificate) cert;
            privateKey = (PrivateKey) keyStore.getKey(keyStoreAlias, JUnitConstants.password.toCharArray());
        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    private void mockSignerCertificateAndKey() {
        Mockito.when(configurationListener.getScepRAInfraCertAliasName()).thenReturn(keyStoreAlias);
        Mockito.when(cryptoService.readCertificate(keyStoreAlias, false)).thenReturn(signerCertificate);
        Mockito.when(cryptoService.readPrivateKey(keyStoreAlias)).thenReturn(privateKey);
    }

}
