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
package com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.config.ConfigurationPropertyNotFoundException;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.AliasNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreFileReaderException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;

/*
 * This class tests CryptoService
 */
@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("unchecked")
public class CryptoServiceTest {

    @InjectMocks
    CryptoService cryptoService;

    @Mock
    Logger logger;

    @Mock
    ConfigurationListener configurationListener;

    @Mock
    KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    KeyStoreFileReader keyStoreFileReader;

    @Mock
    SystemRecorder systemRecorder;

    private KeyStoreInfo keyStoreInfo;
    private Certificate[] certificateChain = new Certificate[1];
    private Certificate[] certificateChain1 = new Certificate[2];
    private Certificate certificate;
    private Certificate certificate1;
    private Certificate certFromTrustStore;
    private Certificate[] certChainFromTrustStore;
    final List<Certificate> certificateList = new ArrayList<Certificate>();
    private KeyStore keyStore;

    private PrivateKey privateKey;

    @Before
    public void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {

        keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
        keyStore.load(CryptoServiceTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());

        certificate = new CryptoServiceTest().getCertificate();
        certificate1 = new CryptoServiceTest().getCertificate();
        readTrustStore();

        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, JUnitConstants.password, JUnitConstants.caName);
        privateKey = (PrivateKey) keyStore.getKey(keyStoreInfo.getAliasName(), keyStoreInfo.getPassword().toCharArray());
        System.setProperty(Constants.STORE_PASSWORD, "C4bCzXyT");
        Mockito.when(configurationListener.getScepRATrustStoreFilePath()).thenReturn(JUnitConstants.trustStoreFilePath);
        Mockito.when(configurationListener.getTrustStoreFileType()).thenReturn(JUnitConstants.jks_keyStoreType);
    }

    @After
    public void destroy() {
        System.clearProperty(Constants.STORE_PASSWORD);
    }

    private Certificate getCertificate() {
        java.security.cert.Certificate cert = null;

        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
            keyStore.load(CryptoServiceTest.class.getResourceAsStream(JUnitConstants.filePath), JUnitConstants.password.toCharArray());
            cert = keyStore.getCertificate(JUnitConstants.caName);

        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
        return cert;
    }

    private void readTrustStore() {
        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.jks_keyStoreType);
            keyStore.load(CryptoServiceTest.class.getResourceAsStream(JUnitConstants.trustStoreFilePath), null);
            certFromTrustStore = keyStore.getCertificate("oam_enm_oam_ca");
            certChainFromTrustStore = new Certificate[] { certFromTrustStore };
        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    /*
     * This method tests the complete CA certificate chain in success scenario
     */
    @Test
    public void testGetCompleteCertificateListFromChain() {
        certificateChain[0] = certificate;
        certificateList.add(certificate);
        assertEquals(cryptoService.getCertificateListFromChain(certificateChain, true), certificateList);
        Mockito.verify(logger).debug("End of getCertificateListFromChain method in CryptoService class");
    }

    /*
     * This method tests the complete CA certificate chain in failure scenario
     */
    @Test
    public void testGetCertificateListFromChain() {
        certificateChain1[0] = certificate;
        certificateChain1[1] = certificate1;
        certificateList.add(certificate);
        certificateList.add(certificate1);
        assertEquals(cryptoService.getCertificateListFromChain(certificateChain1, false), certificateList);
        Mockito.verify(logger).debug("End of getCertificateListFromChain method in CryptoService class");
    }

    /*
     * This method Tests Reading CertificateChain from KeyStore
     */
    @Test
    public void testReadCertificateChain() {
        certificateChain[0] = certificate;
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.when(keyStoreFileReader.readCertificateChain(keyStoreInfo)).thenReturn(certificateChain);
        assertEquals(cryptoService.readCertificateChain(JUnitConstants.caName, false)[0], certificateChain[0]);
        Mockito.verify(logger).debug("End of readCertificateChain method in CryptoService class");
    }

    /*
     * This method Tests Reading CertificateChain from KeyStore to throw BadRequestException when occurs AliasNotFoundException
     */
    @Test(expected = BadRequestException.class)
    public void testReadCertificateChainAliasNotFoundException() {
        certificateChain[0] = certificate;
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenThrow(AliasNotFoundException.class);
        cryptoService.readCertificateChain(JUnitConstants.caName, false);
    }

    /*
     * This method Tests Reading Certificate from KeyStore to throw BadRequestException when occurs AliasNotFoundException
     */
    @Test(expected = BadRequestException.class)
    public void testReadCertificateAliasNotFoundException() {
        certificateChain[0] = certificate;
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenThrow(AliasNotFoundException.class);
        cryptoService.readCertificate(JUnitConstants.caName, false);
    }

    /*
     * This method Tests Reading Private key from KeyStore to throw BadRequestException when occurs AliasNotFoundException
     */
    @Test(expected = BadRequestException.class)
    public void testReadPrivateKeyAliasNotFoundException() {
        certificateChain[0] = certificate;
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        System.setProperty("SCEP_RA_KEYSTORE_PASSWORD_PROPERTY", JUnitConstants.password);
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, JUnitConstants.password, JUnitConstants.caName);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(new AliasNotFoundException("")).when(keyStoreFileReader).readPrivateKey(keyStoreInfo);
        cryptoService.readPrivateKey(JUnitConstants.caName);
        System.clearProperty("SCEP_RA_KEYSTORE_PASSWORD_PROPERTY");
    }

    /*
     * This method tests Reading CertificateChain from KeyStore when there is no KeyStoreHandler present
     */
    @Test(expected = PkiScepServiceException.class)
    public void testReadCertificateChainWithPkiScepServiceException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenThrow(new KeyStoreFileReaderException("KeystoreException"));
        cryptoService.readCertificateChain(JUnitConstants.caName, false);
    }

    /*
     * This method tests Reading Certificate from KeyStore.
     */
    @Test
    public void testReadCertificate() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.when(keyStoreFileReader.readCertificate(keyStoreInfo)).thenReturn(certificate);
        assertEquals(cryptoService.readCertificate("lteipsecnecus", false), certificate);
    }

    /*
     * This method tests Reading Certificate from KeyStore when there is no KeyStoreHandler present
     */
    @Test(expected = PkiScepServiceException.class)
    public void testReadCertificateWithPkiScepServiceException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenThrow(new KeyStoreFileReaderException("KeystoreException"));
        cryptoService.readCertificate("lteipsecnecus", false);
    }

    /*
     * This method tests Reading PrivateKey from KeyStore.
     */
    @Test
    public void testReadPrivateKey() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.when(keyStoreFileReader.readPrivateKey(keyStoreInfo)).thenReturn(privateKey);
        assertEquals(privateKey, cryptoService.readPrivateKey(JUnitConstants.caName));
        Mockito.verify(logger).debug("End of readPrivateKey method in CryptoService class");
    }

    /*
     * This Method Tests Reading privatekey from KeyStore with wrong caname.
     */
    @Test(expected = BadRequestException.class)
    public void testReadPrivateKeyWithBadRequestException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, JUnitConstants.password, "testCA");
        System.setProperty("SCEP_RA_KEYSTORE_PASSWORD_PROPERTY", JUnitConstants.password);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(BadRequestException.class).when(keyStoreFileReader).readPrivateKey(keyStoreInfo);
        cryptoService.readPrivateKey("testCA");
    }

    /*
     * This Method Tests throwing PkiScepServiceException when caught KeyStoreFileReaderException.
     */
    @Test(expected = PkiScepServiceException.class)
    public void testReadPrivateKeyWithPkiScepServiceException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, JUnitConstants.password, "testCA");
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(KeyStoreFileReaderException.class).when(keyStoreFileReader).readPrivateKey(keyStoreInfo);
        cryptoService.readPrivateKey("testCA");
    }

    /*
     * This method tests Reading Certificate from KeyStore with wrong caname
     */
    @Test(expected = BadRequestException.class)
    public void testReadCertificateWithBadRequestException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, "C4bCzXyT", "testCA");
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(BadRequestException.class).when(keyStoreFileReader).readCertificate(keyStoreInfo);
        cryptoService.readCertificate("testCA", false);
    }

    /*
     * This method tests Reading CertificateChain from KeyStore with wrong caname
     */
    @Test(expected = BadRequestException.class)
    public void testReadCertificateChainWithBadRequestException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenReturn(JUnitConstants.filePath);
        Mockito.when(configurationListener.getKeyStoreFileType()).thenReturn(JUnitConstants.keyStoreType);
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.PKCS12, "C4bCzXyT", "testCA");
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(BadRequestException.class).when(keyStoreFileReader).readCertificateChain(keyStoreInfo);
        cryptoService.readCertificateChain("testCA", false);
    }

    /*
     * This method tests Reading Certificate from KeyStore to throw PkiScepServiceException when occurs ConfigurationPropertyNotFoundException
     */
    @Test(expected = PkiScepServiceException.class)
    public void testReadCertificateConfigurationPropertyNotFoundException() {
        Mockito.when(configurationListener.getKeyStoreFilePath()).thenThrow(ConfigurationPropertyNotFoundException.class);
        cryptoService.readCertificate("testCA", false);
    }

    /*
     * This Method Tests Reading KeyStoreInfo
     */
    @Test
    public void testGetKeyStoreInfo() {
        cryptoService.setKeyStoreInfo(keyStoreInfo);
        assertEquals(cryptoService.getKeyStoreInfo(), keyStoreInfo);
    }

    /**
     * This Method Tests Setting KeyStoreInfo
     */
    @Test
    public void testSetKeyStoreInfo() {
        cryptoService.setKeyStoreInfo(keyStoreInfo);
    }

    @Test(expected = PkiScepServiceException.class)
    public void testReadAllCertificates_PkiScepServiceException() {
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, "C4bCzXyT", null);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        cryptoService.readAllCertificates(true);
        Mockito.verify(logger).error("No trust Certificates are found in the trust store");
    }

    @Test
    public void testReadAllCertificates() throws KeyStoreException {
        keyStoreInfo = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, null);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        final Set<X509Certificate> trustCertificaetSet = new HashSet<X509Certificate>();
        trustCertificaetSet.add((X509Certificate) certificate);
        Mockito.when(keyStoreFileReader.readCertificates(keyStoreInfo)).thenReturn(trustCertificaetSet);
        assertFalse(cryptoService.readAllCertificates(true).isEmpty());
    }

    @Test
    public void testReadCertificateFromTrustStore() {
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, JUnitConstants.TRUST_STORE_CERT_CA_NAME);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.when(keyStoreFileReader.getAllAliases(keyStoreInfo)).thenReturn(Arrays.asList(JUnitConstants.TRUST_STORE_CERT_ALIAS_NAME));

        KeyStoreInfo keyStoreInfoNew = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, JUnitConstants.TRUST_STORE_CERT_ALIAS_NAME);
        Mockito.when(keyStoreFileReader.readCertificate(keyStoreInfoNew)).thenReturn(certFromTrustStore);

        final Certificate resultCertificate = cryptoService.readCertificate(JUnitConstants.TRUST_STORE_CERT_CA_NAME, true);
        assertNotNull(resultCertificate);
        assertEquals(resultCertificate.getPublicKey(), certFromTrustStore.getPublicKey());
    }

    @Test(expected = BadRequestException.class)
    public void testReadCertificateFromTrustStore_WithInvalidCAName() {
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, JUnitConstants.TRUST_STORE_CERT_CA_NAME);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(BadRequestException.class).when(keyStoreFileReader).readCertificate(keyStoreInfo);
        cryptoService.readCertificate(JUnitConstants.TRUST_STORE_CERT_CA_NAME, true);
    }

    @Test
    public void testReadCertificateChainFromTrustStore() {
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, JUnitConstants.TRUST_STORE_CERT_CA_NAME);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.when(keyStoreFileReader.getAllAliases(keyStoreInfo)).thenReturn(Arrays.asList(JUnitConstants.TRUST_STORE_CERT_ALIAS_NAME));

        KeyStoreInfo keyStoreInfoNew = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, JUnitConstants.TRUST_STORE_CERT_ALIAS_NAME);
        Mockito.when(keyStoreFileReader.readCertificateChain(keyStoreInfoNew)).thenReturn(certChainFromTrustStore);

        final Certificate[] resultCertificateChain = cryptoService.readCertificateChain(JUnitConstants.TRUST_STORE_CERT_CA_NAME, true);
        assertNotNull(resultCertificateChain);
        assertTrue(resultCertificateChain.equals(certChainFromTrustStore));
    }

    @Test(expected = BadRequestException.class)
    public void testReadCertificateChainFromTrustStore_WithInvalidCAName() {
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo(JUnitConstants.trustStoreFilePath, KeyStoreType.JKS, JUnitConstants.password, JUnitConstants.TRUST_STORE_CERT_CA_NAME);
        Mockito.when(keyStoreFileReaderFactory.getKeystoreFileReaderInstance(keyStoreInfo)).thenReturn(keyStoreFileReader);
        Mockito.doThrow(BadRequestException.class).when(keyStoreFileReader).readCertificate(keyStoreInfo);
        cryptoService.readCertificate(JUnitConstants.TRUST_STORE_CERT_CA_NAME, true);
    }
}
