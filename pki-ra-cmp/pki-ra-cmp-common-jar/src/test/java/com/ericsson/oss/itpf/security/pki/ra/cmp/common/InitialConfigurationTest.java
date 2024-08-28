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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreFileReader;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;

@RunWith(MockitoJUnitRunner.class)
public class InitialConfigurationTest {
    private static final String ISSUERNAME = "TestCA";

    @InjectMocks
    InitialConfiguration initialConfiguration;

    @Mock
    ConfigurationParamsListener configurationParamsListener;

    @Mock
    KeyStoreFileReader keyStoreFileReader;

    @Mock
    KeyStoreInfo vendorTrustStoreInfo;

    @Mock
    KeyStoreInfo caTrustStoreInfo;

    @Mock
    KeyStoreInfo signerKeyStoreInfo;

    @Mock
    Logger logger;

    private static final String KEYSTORE_ALIAS = "racsa_omsas";
    private static Certificate[] certificate = null;
    private static KeyStore keyStore = null;
    private static X509Certificate cert = null;

    @Before
    public void testSetUp() throws Exception {
        setUpTestData();
    }

    @Test
    public void testGetVendorCertificateSet() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        initialConfiguration.getVendorCertificateSet();
        Mockito.verify(configurationParamsListener, Mockito.atLeastOnce()).getVendorTrustStoreFileType();

    }

    @Test
    public void testGetCaCertificateSet() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        initialConfiguration.getCaCertificateSet();
        Mockito.verify(configurationParamsListener, Mockito.atLeastOnce()).getCATrustStoreFileType();

    }

    @Test
    public void testGetSignerCertificate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        initialConfiguration.getSignerCertificate(ISSUERNAME);
        Mockito.verify(keyStoreFileReader).readCertificate(signerKeyStoreInfo);
    }

    @Test
    public void testGetKeyPair() throws FileNotFoundException, IOException, GeneralSecurityException {
        initialConfiguration.getKeyPair(ISSUERNAME);
        Mockito.verify(keyStoreFileReader).readCertificate(signerKeyStoreInfo);
    }

    @Test
    public void testGetTrustedCerts() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        initialConfiguration.getTrustedCerts(Constants.TYPE_INIT_REQ);
        initialConfiguration.getTrustedCerts(Constants.TYPE_KEY_UPDATE_REQ);
        Mockito.verify(configurationParamsListener, Mockito.atLeastOnce()).getVendorTrustStoreFileType();
    }

    @Test
    public void testGetRACertificateChain() throws GeneralSecurityException, FileNotFoundException, IOException {
        initialConfiguration.getRACertificateChain(ISSUERNAME);
        Mockito.verify(keyStoreFileReader).readCertificateChain(signerKeyStoreInfo);
    }

    @Test(expected = InvalidInitialConfigurationException.class)
    public void testGetTrustedCertsForDefault() {
        initialConfiguration.getTrustedCerts(Constants.INVALID_REQUEST);
    }

    private KeyStore getKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        File keyStorePath = null;
        keyStore = KeyStore.getInstance("jks");
        keyStorePath = new File(this.getClass().getResource("/CertificatesTest/" + "racsa_omsas.jks").getPath());
        keyStore.load(new FileInputStream(keyStorePath), new String(new byte[] { 115, 101, 99, 109, 103, 109, 116 }).toCharArray());
        return keyStore;
    }

    private void setUpTestData() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        keyStore = getKeyStore();
        certificate = keyStore.getCertificateChain(KEYSTORE_ALIAS);
        cert = (X509Certificate) keyStore.getCertificateChain(KEYSTORE_ALIAS)[0];
        Mockito.when(configurationParamsListener.getVendorTrustStoreFileType()).thenReturn(keyStore.toString());
        Mockito.when(configurationParamsListener.getCATrustStoreFileType()).thenReturn(keyStore.toString());
        Mockito.when(configurationParamsListener.getKeyStoreFileType()).thenReturn(keyStore.toString());
        Mockito.when(keyStoreFileReader.readCertificate(signerKeyStoreInfo)).thenReturn(cert);
        Mockito.when(keyStoreFileReader.readCertificateChain(signerKeyStoreInfo)).thenReturn(certificate);
    }

    @Test
    public synchronized void testReInitializeVendorCertificates() {

        initialConfiguration.reInitializeVendorCertificates();

        Mockito.verify(logger).info("Vendor Trust Store file Path is" + configurationParamsListener.getVendorTrustStoreFileType());
    }

    @Test(expected = InvalidInitialConfigurationException.class)
    public synchronized void testReInitializeVendorCertificatesKeyStoreException() throws KeyStoreException {

        Mockito.when(keyStoreFileReader.readCertificates(vendorTrustStoreInfo)).thenThrow(new KeyStoreException());

        initialConfiguration.reInitializeVendorCertificates();
    }

    @Test
    public synchronized void reinitializeCaCertificates() {

        initialConfiguration.reInitializeCACertificates();

        Mockito.verify(logger).info("CA Trust Store Path is" + configurationParamsListener.getCATrustStoreFileType());
    }

    @Test
    public void testGetCertificateforEventSigning() {
        initialConfiguration.getCertificateforEventSigning();
        Mockito.verify(logger).debug("Key Store Path is" + configurationParamsListener.getKeyStorePath());

    }

    @Test
    public void testGetPrivateKeyForSigning() {
        initialConfiguration.getPrivateKeyForSigning();
        Mockito.verify(logger).debug("Key Store Path is" + configurationParamsListener.getKeyStorePath());
    }

}
