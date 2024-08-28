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
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.GetCaCertResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.ProtocolException;
import com.ericsson.oss.itpf.security.pki.ra.scep.instrumentation.SCEPInstrumentationBean;

/**
 * This class tests GetCaCertHandler
 */
@RunWith(MockitoJUnitRunner.class)
public class GetCaCertHandlerTest {

    @InjectMocks
    private GetCaCertHandler getCACertHandler;

    @Mock
    private GetCaCertResponseBuilder getCACertResponseBuilder;

    @Mock
    private PkiScepResponse pkiScepResponse;

    @Mock
    private PkiScepRequest pkiScepRequest;

    @Mock
    private CryptoService cryptoService;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @InjectMocks
    private KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    private KeyStoreFileReaderFactory keyStoreFileReaderFactoryNew;

    @Mock
    SCEPInstrumentationBean scepInstrumentationBean;

    private KeyStoreInfo keyStoreInfo;

    private ArrayList<Certificate> certificateList = null;

    @Before
    public void setUp() throws ProtocolException {
        keyStoreInfo = getCorrectKeyStoreInfo();
    }

    /**
     * This method performs processing of GetCACert Request and asserts that response is not null.
     */

    @Test
    public void testHandle() {

        try {
            pkiScepRequest.setCaName(JUnitConstants.caName);
            Mockito.when(pkiScepRequest.getCaName()).thenReturn(JUnitConstants.caName);
            Mockito.when(cryptoService.getKeyStoreInfo()).thenReturn(keyStoreInfo);

            final KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());

            keyStore.load(GetCaCertHandlerTest.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());

            final Certificate[] certChain = keyStore.getCertificateChain(keyStoreInfo.getAliasName());
            Mockito.when(cryptoService.readCertificateChain(pkiScepRequest.getCaName(), false)).thenReturn(certChain);
            Mockito.when(cryptoService.getCertificateListFromChain(certChain, false)).thenReturn(certificateList);
            Assert.assertNotNull(getCACertHandler.handle(pkiScepRequest));
            Mockito.verify(logger).debug("End of handle method in GetCaCertHandler class");
        } catch (ProtocolException | KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
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
        for (int i = 0; i < 2; i++) {
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
    public KeyStoreInfo getCorrectKeyStoreInfo() {
        final KeyStoreInfo keyStore = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.valueOf(JUnitConstants.keyStoreType), JUnitConstants.password, JUnitConstants.caName);
        return keyStore;
    }

}
