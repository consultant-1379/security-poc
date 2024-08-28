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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateConversionException;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.ProtocolException;

/**
 * This class Tests GetCaCertResponseBuilder.
 */
@RunWith(MockitoJUnitRunner.class)
public class GetCaCertResponseBuilderTest {

    @InjectMocks
    private GetCaCertResponseBuilder getCACertResponseBuilder;

    @InjectMocks
    private KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    private PkiScepResponse pkiScepResponse;

    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    private ArrayList<Certificate> certificateList;

    private KeyStoreInfo keyStoreInfo;

    private Pkcs7ScepResponseData pkcs7ScepResponseData;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @Before
    public void setUp() {
        keyStoreInfo = getKeyStoreInfo();
        pkcs7ScepResponseData = new Pkcs7ScepResponseData();
    }

    /**
     * This method prepares CaCertReponse and Asserts that Certificates present in the keySote Equal or not.
     */
    @Test
    public void testCreateGetCACertResponse() {

        try {
            final KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
            keyStore.load(GetCaCertResponseBuilderTest.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());
            final Certificate[] certChain = keyStore.getCertificateChain(keyStoreInfo.getAliasName());
            certificateList = getCertificateList(certChain);
            final byte[] responseData = getCACertResponseBuilder.buildGetCaCertResponse(certificateList, pkcs7ScepResponseData);
            Mockito.verify(logger).debug("End of createGetCaCertResponse method in GetCaCertResponseBuilder class");
            final Certificate[] certChain1 = getCertChainFromStore(responseData);
            Assert.assertArrayEquals("Both certChains are not equal", certChain, certChain1);
        } catch (ProtocolException | KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            Assert.fail(e.getMessage());
        }

    }

    /**
     * getKeyStoreInfo will get the KeyStroreInfo for a given KeyStore parameters.
     * 
     * @return KeyStore information for the KeyStore parameters.
     */
    public KeyStoreInfo getKeyStoreInfo() {
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

        for (int i = 0; i < 2; i++) {
            certificateList.add(certificates[i]);
        }
        return certificateList;
    }

    /**
     * getCertChainFromStore will provide a certificate array for a given response message
     * 
     * @param response
     *            is the response message
     * @return is the certificate array
     */
    public static Certificate[] getCertChainFromStore(final byte[] response) {
        ArrayList<Certificate> certificaArrayList = null;
        try {
            final CMSSignedData cmsSignedData = new CMSSignedData(response);
            final SignedData signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());

            final ASN1Set certificaAsn1Set = signedData.getCertificates();

            certificaArrayList = getCertificates(certificaAsn1Set.getObjects());

        } catch (final CMSException | CertificateConversionException | IOException e) {
            Assert.fail(e.getMessage());
        }
        return certificaArrayList.toArray(new Certificate[certificaArrayList.size()]);
    }

    /**
     * getCertificates method will fetch the list of certificates from certificates Enumeration
     * 
     * @param certicEnumeration
     *            is the Certificate Enumeration
     * @return certificateList is the certificate list for a given certificates Enumeration
     */
    @SuppressWarnings("rawtypes")
    private static ArrayList<Certificate> getCertificates(final Enumeration certicEnumeration) throws CertificateConversionException, IOException {
        final ArrayList<Certificate> certificaArrayList = new ArrayList<Certificate>();

        while (certicEnumeration.hasMoreElements()) {
            final ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
            final DEROutputStream derOutPutStream = new DEROutputStream(byteOutputStream);

            try {
                derOutPutStream.writeObject((ASN1Encodable) certicEnumeration.nextElement());
            } catch (final IOException e) {
                Assert.fail(e.getMessage());
            }

            final X509Certificate certificate = CertificateUtility.getCertificateFromByteArray(byteOutputStream.toByteArray());
            certificaArrayList.add(certificate);
        }
        return certificaArrayList;
    }

}
