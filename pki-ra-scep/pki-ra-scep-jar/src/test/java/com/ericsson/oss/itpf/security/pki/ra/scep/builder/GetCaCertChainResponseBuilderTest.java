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

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.bouncycastle.cms.CMSSignedData;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.ProtocolException;

/**
 * This class test GetCaCertChainResponseBuilder
 */
@RunWith(MockitoJUnitRunner.class)
public class GetCaCertChainResponseBuilderTest {

    @InjectMocks
    private GetCaCertChainResponseBuilder getCaCertChainResponseBuilder;

    @Mock
    private KeyStoreFileReader keyStoreFileReader;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    CMSSignedData cMSSignedData;

    @Mock
    private KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    private KeyStoreInfo keyStoreInfo;

    private ArrayList<Certificate> certificateList = null;

    @Mock
    Pkcs7ScepResponseData pkcs7ScepResponseData;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @Before
    public void setUp() {
        keyStoreInfo = getKeyStoreInfo();
        // pkcs7ScepResponseData = new Pkcs7ScepResponseData();
    }

    /**
     * Reads CertChain From KeyStore and asserts that Certificates fetching from code are equal.
     */

    @Test
    public void testCreateGetCaCertChainResponse() {
        try {
            final KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
            keyStore.load(GetCaCertChainResponseBuilderTest.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());
            pkcs7ScepResponseData = new Pkcs7ScepResponseData();
            final Certificate[] certChain = keyStore.getCertificateChain(keyStoreInfo.getAliasName());
            certificateList = getCertificateList(certChain);
            final byte[] response = getCaCertChainResponseBuilder.buildGetCaCertChainResponse(certificateList, pkcs7ScepResponseData);
            Mockito.verify(logger).debug("End of  createGetCACertChainResponse method of createGetCACertChainResponse class");
            final Certificate[] certChain1 = GetCaCertResponseBuilderTest.getCertChainFromStore(response);
            Assert.assertArrayEquals("Both certChains are equal", certChain, certChain1);
        } catch (final NoSuchAlgorithmException | CertificateException | IOException | ProtocolException | KeyStoreException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException.class)
    public void testCreateGetCaCertChainResponseIOException() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

        final KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
        keyStore.load(GetCaCertChainResponseBuilderTest.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());

        final Certificate[] certChain = keyStore.getCertificateChain(keyStoreInfo.getAliasName());
        certificateList = getCertificateList(certChain);

        Mockito.doThrow(IOException.class).when(pkcs7ScepResponseData).setAddSignerInfo(false);

        final byte[] response = getCaCertChainResponseBuilder.buildGetCaCertChainResponse(certificateList, pkcs7ScepResponseData);
        final Certificate[] certChain1 = GetCaCertResponseBuilderTest.getCertChainFromStore(response);
        Assert.assertArrayEquals("Both certChains are equal", certChain, certChain1);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException.class)
    public void testCreateGetCaCertChainResponsePkiScepServiceException() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

        final KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
        keyStore.load(GetCaCertChainResponseBuilderTest.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());

        final Certificate[] certChain = keyStore.getCertificateChain(keyStoreInfo.getAliasName());
        certificateList = getCertificateList(certChain);

        Mockito.doThrow(PkiScepServiceException.class).when(pkcs7ScepResponseData).setAddSignerInfo(false);

        final byte[] response = getCaCertChainResponseBuilder.buildGetCaCertChainResponse(certificateList, pkcs7ScepResponseData);
        Mockito.verify(logger).debug("End of  createGetCACertChainResponse method of createGetCACertChainResponse class");
        final Certificate[] certChain1 = GetCaCertResponseBuilderTest.getCertChainFromStore(response);
        Assert.assertArrayEquals("Both certChains are equal", certChain, certChain1);

    }

    /**
     * getKeyStoreInfo will get the KeyStroreInfo for a given KeyStore parameters.
     * 
     * @return KeyStore information for the KeyStore parameters.
     */
    private KeyStoreInfo getKeyStoreInfo() {
        final KeyStoreInfo keyStore = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.valueOf(JUnitConstants.keyStoreType), JUnitConstants.password, JUnitConstants.caName);
        return keyStore;

    }

    /**
     * getCertificateList method will fetch the list of certificates
     * 
     * @param certificates
     *            is the Certificate array
     * @return certificateList is the certificate list for a given certificates array
     */
    private ArrayList<Certificate> getCertificateList(final Certificate[] certificates) {
        final ArrayList<Certificate> certificateList = new ArrayList<Certificate>();

        for (int i = 0; i < certificates.length; i++) {

            certificateList.add(certificates[i]);
        }
        return certificateList;
    }

}
