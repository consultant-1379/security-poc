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

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.Pkcs7ScepRequestSetUpData;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.validator.AlgorithmValidator;

/**
 * This method Tests EnvelopedDataProcessor
 */
@RunWith(MockitoJUnitRunner.class)
public class EnvelopedDataProcessorTest {

    @Mock
    private SystemRecorder systemRecorder;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private String successPkcs = "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";

    private String invalidMsgType = "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";

    private String getCrl = "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";

    private Pkcs7ScepRequestData pkcs7ScepRequestData;
    private CMSSignedData cmsSignedData;
    private byte[] message = null;
    private SignedData signedData;
    private String caName = "lteipsecnecus";
    private PrivateKey privateKey = null;

    @Mock
    private CryptoService cryptoService;

    @InjectMocks
    private EnvelopedDataProcessor envelopedDataProcessor;

    @Mock
    private Logger logger;

    @Mock
    private CMSEnvelopedData cmsEnvelopedData;

    @Mock
    ConfigurationListener configurationListener;

    @Mock
    KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    KeyStoreFileReader keyStoreFileReader;

    @Mock
    private AlgorithmValidator algValidator;
    private KeyStore keyStore;
    private KeyStoreInfo keyStoreInfo;
    final private String encryprtionAlgOid = "1.2.840.113549.3.7";
    final private String symmetricAlgOID = "1.2.840.113549.1.1.1";

    @Before
    public void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {

        keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
        keyStore.load(EnvelopedDataProcessorTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());

        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, JUnitConstants.password, JUnitConstants.caName);
        privateKey = (PrivateKey) keyStore.getKey(keyStoreInfo.getAliasName(), keyStoreInfo.getPassword().toCharArray());

        keyStoreFileReader = new JksPkcs12KeyStoreFileReader();

        System.setProperty(Constants.STORE_PASSWORD, "C4bCzXyT");
    }

    /**
     * This tests extract envelopedData for given PKCS Request data
     */
    @Test
    public void testGetExtractEnvelopedData() {
        setUpData(successPkcs);
        caName = "Root";
        Mockito.when(cmsEnvelopedData.getEncryptionAlgOID()).thenReturn(encryprtionAlgOid);
        Mockito.when(algValidator.isSupportedAlgorithm(encryprtionAlgOid, "CmsEnvelopedData Encyrption", AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(algValidator.isSupportedAlgorithm(symmetricAlgOID, "RecipientInformation Key Encryption", AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(cryptoService.readPrivateKey(caName)).thenReturn(privateKey);
        envelopedDataProcessor.extractEnvelopedData(signedData, "Root", pkcs7ScepRequestData);
        Mockito.verify(logger).debug("End of extractEnvelopedData method of EnvelopedDataProcessor");
        assertNotNull(pkcs7ScepRequestData.getPkcsReqinfo());
    }

    /**
     * This tests extract envelopedData for PKCSReq with UnSupported AssymetricAlgorithm
     */
    @Test(expected = UnSupportedAlgException.class)
    public void testUnSupportedASymKeyAlgException() {
        setUpData(successPkcs);
        Mockito.when(cmsEnvelopedData.getEncryptionAlgOID()).thenReturn(encryprtionAlgOid);
        Mockito.when(algValidator.isSupportedAlgorithm(encryprtionAlgOid, "CmsEnvelopedData Encyrption", AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(algValidator.isSupportedAlgorithm(symmetricAlgOID, "RecipientInformation Key Encryption", AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(false);
        envelopedDataProcessor.extractEnvelopedData(signedData, "Root", pkcs7ScepRequestData);
    }

    /**
     * This tests extract envelopedData for PKCSReq with UnSupported SymetricAlgorithm
     */
    @Test(expected = UnSupportedAlgException.class)
    public void testUnSupportedSymKeyAlgException() {
        setUpData(successPkcs);

        Mockito.when(cmsEnvelopedData.getEncryptionAlgOID()).thenReturn(encryprtionAlgOid);
        Mockito.when(algValidator.isSupportedAlgorithm(encryprtionAlgOid, "CmsEnvelopedData Encyrption", AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenReturn(false);
        envelopedDataProcessor.extractEnvelopedData(signedData, "Root", pkcs7ScepRequestData);
    }

    /**
     * This tests extract envelopedData for PKCSReq with UnSupported MsgType
     */
    @Test(expected = UnSupportedMsgTypeException.class)
    public void testInvalidMsgType() {
        setUpData(invalidMsgType);
        final String encryprtionAlgOid = "1.3.14.3.2.7";

        Mockito.when(cmsEnvelopedData.getEncryptionAlgOID()).thenReturn(encryprtionAlgOid);
        Mockito.when(algValidator.isSupportedAlgorithm(encryprtionAlgOid, "CmsEnvelopedData Encyrption", AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(algValidator.isSupportedAlgorithm(symmetricAlgOID, "RecipientInformation Key Encryption", AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(cryptoService.readPrivateKey(caName)).thenReturn(privateKey);
        envelopedDataProcessor.extractEnvelopedData(signedData, "Root", pkcs7ScepRequestData);
    }

    /**
     * This tests extract envelopedData for PKCSReq with InvalidMsgType
     */

    @Test(expected = NotImplementedMsgTypeException.class)
    public void testNotImplementedMsgType() {
        setUpData(getCrl);
        final String encryprtionAlgOid = "1.3.14.3.2.7";
        Mockito.when(cmsEnvelopedData.getEncryptionAlgOID()).thenReturn(encryprtionAlgOid);
        Mockito.when(algValidator.isSupportedAlgorithm(encryprtionAlgOid, "CmsEnvelopedData Encyrption", AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(algValidator.isSupportedAlgorithm(symmetricAlgOID, "RecipientInformation Key Encryption", AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(true);
        Mockito.when(cryptoService.readPrivateKey(caName)).thenReturn(privateKey);
        envelopedDataProcessor.extractEnvelopedData(signedData, "Root", pkcs7ScepRequestData);
    }

    /**
     * This Method Tests CertInitialEnvelopedData
     */

    private void setUpData(final String msg) {
        message = msg.getBytes();
        pkcs7ScepRequestData = new Pkcs7ScepRequestData();
        if (StringUtility.isBase64(new String(message))) {
            message = Base64.decode(message);
        }
        try {
            cmsSignedData = new CMSSignedData(message);
        } catch (final CMSException e) {
            Assert.fail(e.getMessage());
        }
        signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());
        pkcs7ScepRequestData = Pkcs7ScepRequestSetUpData.getPkcs7ScepRequest(message);
        privateKey = Pkcs7ScepRequestSetUpData.getPrivateKey(JUnitConstants.caName, JUnitConstants.filePath, JUnitConstants.password);
    }

}