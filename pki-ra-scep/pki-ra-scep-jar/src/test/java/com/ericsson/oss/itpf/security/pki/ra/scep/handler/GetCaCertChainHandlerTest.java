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
package com.ericsson.oss.itpf.security.pki.ra.scep.handler;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.GetCaCertChainResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.ProtocolException;

/**
 * This class Tests GetCaCertChainHandler
 */
@RunWith(MockitoJUnitRunner.class)
public class GetCaCertChainHandlerTest {

    @InjectMocks
    private GetCaCertChainHandler getCaCertChainHandler;

    @Mock
    GetCaCertChainResponseBuilder getCaCertChainResponseBuilder;

    @Mock
    private PkiScepRequest pkiScepRequest;

    @Mock
    private CryptoService cryptoService;

    @Mock
    private PkiScepResponse pkiScepResponse;

    @Mock
    private com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse PkiScepResponse;

    @Mock
    private static Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @InjectMocks
    private KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    private KeyStoreFileReaderFactory keyStoreFileReaderFactoryNew;

    private KeyStoreInfo keyStoreInfo;

    private ArrayList<Certificate> certificateList = null;

    Pkcs7ScepResponseData pkcs7ScepResponseData;

    String response = "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";

    @Before
    public void setUp() {
        try {
            keyStoreInfo = getKeyStoreInfo();
            pkcs7ScepResponseData = new Pkcs7ScepResponseData();
        } catch (ProtocolException e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * This method performs processing of GetCACertChain Request and asserts that response is not null.
     */
    @Test
    public void testHandle() {

        try {
            pkiScepRequest.setCaName(JUnitConstants.rootCaName);

            Mockito.when(pkiScepRequest.getCaName()).thenReturn(JUnitConstants.rootCaName);
            Mockito.when(cryptoService.getKeyStoreInfo()).thenReturn(keyStoreInfo);
            final KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
            keyStore.load(GetCaCertChainHandlerTest.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());
            final Certificate[] certChain = keyStore.getCertificateChain(keyStoreInfo.getAliasName());
            certificateList = getCertficateList(certChain);
            Mockito.when(cryptoService.readCertificateChain(pkiScepRequest.getCaName(), false)).thenReturn(certChain);
            Mockito.when(cryptoService.getCertificateListFromChain(certChain, true)).thenReturn(certificateList);
            pkiScepResponse = getCaCertChainHandler.handle(pkiScepRequest);
            Mockito.verify(logger).debug("End of handle method in GetCaCertChainHandler class");
        } catch (KeyStoreException | ProtocolException | CertificateException | NoSuchAlgorithmException | IOException e) {
            Assert.fail(e.getMessage());
        }

    }

    /**
     * getCertficateList will provide the certificate list for a given certificate chain
     * 
     * @param certChain
     *            is the array of the certificate chain
     * @return certificateList is the list of the certificates
     */
    public ArrayList<Certificate> getCertficateList(final Certificate[] certChain) {
        ArrayList<Certificate> certificateList = null;
        for (int i = 0; i < certChain.length; i++) {
            certificateList = new ArrayList<Certificate>();
            certificateList.add(certChain[i]);
        }
        return certificateList;
    }

    /**
     * getKeyStoreInfo will provide the keyStore information for given keyStore parameters
     * 
     * @return keyStore information for given keyStoreparameters
     */
    public KeyStoreInfo getKeyStoreInfo() {

        final KeyStoreInfo keyStore = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.valueOf(JUnitConstants.keyStoreType), JUnitConstants.password, JUnitConstants.caName);

        return keyStore;
    }
}
